// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {FHE, euint64} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {ERC7984} from "@openzeppelin/confidential-contracts/token/ERC7984/ERC7984.sol";
import {ERC7984ERC20Wrapper} from "@openzeppelin/confidential-contracts/token/ERC7984/extensions/ERC7984ERC20Wrapper.sol";
import {IUnwrapProofVerifier} from "./IUnwrapProofVerifier.sol";
import {KMS_SHARES, KmsUserDecryption} from "./KmsUserDecryption.sol";
import {KmsVerifierView} from "./KmsVerifierView.sol";

/**
 * @title SingleTxUnwrapWrapper
 * @notice OpenZeppelin's {ERC7984ERC20Wrapper} with two one-transaction unwraps. Both consume a Zama
 *         KMS *user* decryption of the holder's live balance handle, which the holder requests
 *         off-chain (no transaction) and decrypts locally — the KMS nodes' own signatures over the
 *         decrypted shares are the trust anchor, checked here against `KMSVerifier`'s signer set.
 *
 *         - {unwrapWithProof}: any amount, the balance stays private. The contract checks the nodes'
 *           signatures over the share digests; a zero-knowledge proof shows the hidden shares behind
 *           those digests reconstruct to a balance >= amount. Proofs come from `circuits/noir`
 *           (UltraHonk) or `circuits/circom` (Groth16): same statement, same public inputs.
 *         - {unwrapAllWithShares}: the whole balance, no proof. The shares go in calldata; the
 *           contract checks the signatures, reconstructs and decodes the balance itself.
 *
 *         The OpenZeppelin two-step {unwrap} → {finalizeUnwrap} stays available.
 *
 * @dev Both paths bind the shares to (live balance handle of `from`, `from`, Gateway domain) through
 *      the signed link, so a burn or any incoming transfer makes old shares useless. That is the
 *      replay guard; it also means an incoming transfer while an unwrap is in flight makes the holder
 *      decrypt again. The signer set and Gateway domain are read live from `KMSVerifier`; the circuit
 *      and {KmsUserDecryption} are fixed to n = 13, t = 4.
 */
contract SingleTxUnwrapWrapper is ERC7984ERC20Wrapper, ZamaEthereumConfig {
    /// @param parties    party ids (1-based index into `KMSVerifier.getKmsSigners()`)
    /// @param digests    the SHA-256 digests the nodes signed
    /// @param signatures 9 × 65-byte low-s signatures (r ‖ s ‖ v), in `parties` order
    /// @param pkKeccak   keccak256 of the user decryption's single-use ML-KEM public key
    struct SignedDigests {
        uint8[KMS_SHARES] parties;
        bytes32[KMS_SHARES] digests;
        bytes signatures;
        bytes32 pkKeccak;
    }

    /// @param shares     9 × 256-byte decrypted shares, in `parties` order
    /// @param poly       the sharing polynomial, (t + 1) × 4 ring elements × 64 bytes
    /// @param encKeyHash the H(enc_key) the nodes signed over
    struct RevealedShares {
        uint8[KMS_SHARES] parties;
        bytes shares;
        bytes signatures;
        bytes poly;
        bytes32 pkKeccak;
        bytes32 encKeyHash;
    }

    IUnwrapProofVerifier public immutable verifier;

    event UnwrappedWithProof(address indexed from, address indexed to, uint64 amount);
    event UnwrappedWithShares(address indexed from, address indexed to, uint64 amount);

    error ProofInvalid();

    constructor(
        IERC20 underlying_,
        string memory name_,
        string memory symbol_,
        IUnwrapProofVerifier verifier_
    ) ERC7984(name_, symbol_, "") ERC7984ERC20Wrapper(underlying_) {
        verifier = verifier_;
    }

    /// @notice Burns `amount` from `from` and sends `amount * rate()` underlying to `to`, given the
    ///         nodes' signed share digests and a proof that the shares behind them decode to >= amount.
    function unwrapWithProof(
        address from,
        address to,
        uint64 amount,
        SignedDigests calldata signed,
        bytes calldata proof
    ) external {
        _authorize(from, to);
        bytes32 linkHash = currentLink(from, signed.pkKeccak);
        bytes32[KMS_SHARES] memory digests = signed.digests;
        KmsUserDecryption.checkSignedDigests(KmsVerifierView.signers(), signed.parties, digests, signed.signatures);
        _verifyProof(proof, KmsUserDecryption.publicInputs(linkHash, from, amount, signed.parties, digests));
        _release(from, to, amount);
        emit UnwrappedWithProof(from, to, amount);
    }

    /// @notice Burns the whole balance of `from` and sends it to `to`, given the nodes' signed
    ///         decryption shares in the clear. Reveals the balance — which the unwrap makes public anyway.
    function unwrapAllWithShares(address from, address to, RevealedShares calldata revealed) external {
        _authorize(from, to);
        bytes32 linkHash = currentLink(from, revealed.pkKeccak);
        if (revealed.shares.length != KmsUserDecryption.SHARES * KmsUserDecryption.SHARE_BYTES) {
            revert KmsUserDecryption.MalformedShares();
        }
        bytes32[KMS_SHARES] memory digests;
        for (uint256 i; i < KmsUserDecryption.SHARES; ++i) {
            digests[i] = KmsUserDecryption.shareDigest(
                revealed.shares[i * KmsUserDecryption.SHARE_BYTES:(i + 1) * KmsUserDecryption.SHARE_BYTES],
                linkHash,
                from,
                revealed.encKeyHash
            );
        }
        KmsUserDecryption.checkSignedDigests(KmsVerifierView.signers(), revealed.parties, digests, revealed.signatures);
        uint64 balance = KmsUserDecryption.reconstruct(revealed.parties, revealed.shares, revealed.poly);
        _release(from, to, balance);
        emit UnwrappedWithShares(from, to, balance);
    }

    /// @notice The link a user decryption of `from`'s current balance with key `pkKeccak` is bound to.
    function currentLink(address from, bytes32 pkKeccak) public view returns (bytes32) {
        return
            KmsUserDecryption.link(
                euint64.unwrap(confidentialBalanceOf(from)),
                from,
                pkKeccak,
                KmsVerifierView.decryptionDomainSeparator()
            );
    }

    /// @dev The generated verifiers revert with bare selectors on most failures and return false on
    ///      others; both surface as {ProofInvalid}.
    function _verifyProof(bytes calldata proof, bytes32[] memory inputs) private view {
        try verifier.verify(proof, inputs) returns (bool verified) {
            require(verified, ProofInvalid());
        } catch {
            revert ProofInvalid();
        }
    }

    function _authorize(address from, address to) private view {
        require(to != address(0), ERC7984InvalidReceiver(to));
        require(from == msg.sender || isOperator(from, msg.sender), ERC7984UnauthorizedSpender(from, msg.sender));
    }

    /// @dev The decryption shows the balance covers `amount`, so the burn removes exactly `amount`.
    function _release(address from, address to, uint64 amount) private {
        _burn(from, FHE.asEuint64(amount));
        SafeERC20.safeTransfer(IERC20(underlying()), to, amount * rate());
    }
}
