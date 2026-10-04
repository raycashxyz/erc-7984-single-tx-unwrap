// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {ZamaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

interface IKMSVerifierSigners {
    function getKmsSigners() external view returns (address[] memory);
}

/**
 * @title KmsVerifierView
 * @notice Live reads of the host chain's `KMSVerifier`: the KMS signer set in party order, and the
 *         EIP-712 domain of the Gateway `Decryption` contract the nodes sign under. Reading them on
 *         every call (instead of configuring them) makes a KMS signer rotation take effect at once.
 */
library KmsVerifierView {
    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    function signers() internal view returns (address[] memory) {
        return IKMSVerifierSigners(kmsVerifier()).getKmsSigners();
    }

    function decryptionDomainSeparator() internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifyingContract, , ) = IERC5267(
            kmsVerifier()
        ).eip712Domain();
        return
            keccak256(
                abi.encode(
                    EIP712_DOMAIN_TYPEHASH,
                    keccak256(bytes(name)),
                    keccak256(bytes(version)),
                    chainId,
                    verifyingContract
                )
            );
    }

    function kmsVerifier() private view returns (address) {
        return ZamaConfig.getEthereumCoprocessorConfig().KMSVerifierAddress;
    }
}
