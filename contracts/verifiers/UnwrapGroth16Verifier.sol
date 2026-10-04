// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract UnwrapGroth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 16428432848801857252194528405604668803277877773566238944394625302971855135431;
    uint256 constant alphay  = 16846502678714586896801519656441059708016666274385668027902869494772365009666;
    uint256 constant betax1  = 3182164110458002340215786955198810119980427837186618912744689678939861918171;
    uint256 constant betax2  = 16348171800823588416173124589066524623406261996681292662100840445103873053252;
    uint256 constant betay1  = 4920802715848186258981584729175884379674325733638798907835771393452862684714;
    uint256 constant betay2  = 19687132236965066906216944365591810874384658708175106803089633851114028275753;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 4851426597022823786907877334737154409167695502380027424369426948198893507184;
    uint256 constant deltax2 = 9404675571860619871945055269290914124070768756033131938530456090950892834686;
    uint256 constant deltay1 = 146568359890045731849828612883918882848476948135520618951009271015696422103;
    uint256 constant deltay2 = 13077658312332619908263643285541460200237581924254252882761324030860735600318;

    
    uint256 constant IC0x = 13826472318221377749414811792232336444177885416582926989886326580677202005434;
    uint256 constant IC0y = 484981515275087231680681126086815141254668279765641659185543376214770203789;
    
    uint256 constant IC1x = 21530420686088882785769653091800334203968113783131310735689149909957321032892;
    uint256 constant IC1y = 16246876285614777802501595252388922531964735915993567122940051973790227665923;
    
    uint256 constant IC2x = 15010725163091735728956244090814804268441999752333107103327376919619349609211;
    uint256 constant IC2y = 16270980133789439573261591217095938160377076940679175756408953912088318408359;
    
    uint256 constant IC3x = 5736680780378043066054902947800655663027002698435824436417632561952474029676;
    uint256 constant IC3y = 1457451040353763610944329392446648552172600995694225402654392724673603864101;
    
    uint256 constant IC4x = 5342772254372664129197841655963237397359642685331153310329685497491665709381;
    uint256 constant IC4y = 19837840241931663450647372399094768612835621004805811370284229348144486316186;
    
    uint256 constant IC5x = 7679799240398018120513368050586700574805031568201390331010677328557890791536;
    uint256 constant IC5y = 20067801270394610180803695225508521099037659898047969269362451202043833967194;
    
    uint256 constant IC6x = 12694932158733794914251423028886928825585986252124582845801869656544933617180;
    uint256 constant IC6y = 17271451484461523322327822011371902143036805172788773563368112895869577753666;
    
    uint256 constant IC7x = 14644208562561912739602946965426797597990904626712264704457099419598105558551;
    uint256 constant IC7y = 11847193328402577010517278155083984141454780386426031009100100582153360368456;
    
    uint256 constant IC8x = 9413813315529793819214698427279807180901840843949816925022426227712281191196;
    uint256 constant IC8y = 12468956515727262629262725141781333860487859553382206151716618713140706437965;
    
    uint256 constant IC9x = 18589727324125912149541876739738281115012725153316964773033113278461657503350;
    uint256 constant IC9y = 19445236684925301576814240593660678382903641047668851972095379067414297487482;
    
    uint256 constant IC10x = 15221720797636636114045974949494560520093867954949229733237075048163710014908;
    uint256 constant IC10y = 5343017619541417794911561935069512786584641987859068209294423365779459525528;
    
    uint256 constant IC11x = 18533900468649331998790557566918340671957414021588001317644863037672687803645;
    uint256 constant IC11y = 20884291071267508882067835082384228873950047220504190777881721177093755319227;
    
    uint256 constant IC12x = 20191733333386659630355929631834703325312635631503144542134823889117409975622;
    uint256 constant IC12y = 17285218858585744413207033185719593253233314351233385038689092576508988516433;
    
    uint256 constant IC13x = 2413459877906938433014049068654749440041584494996568537337391463169296372702;
    uint256 constant IC13y = 14018575535726893791323758410762488979901878341693081388192785384978403349698;
    
    uint256 constant IC14x = 15767954358413660446775722977388877940382343582998231925433299220899412655925;
    uint256 constant IC14y = 18493449889639008941725560018174862425461817593106472577748958583568210003046;
    
    uint256 constant IC15x = 17495347492895801907335436050549698106251360538752956012928348591794556685981;
    uint256 constant IC15y = 9176681972996671570049222009484869393099797933242552254877392963854052317343;
    
    uint256 constant IC16x = 5789179207210903080832051928568381544193087393813957846584292050493033584332;
    uint256 constant IC16y = 21219285613454955009703909015363956454590886521913136450641124757850201916454;
    
    uint256 constant IC17x = 12305991458839187393054002950708598915447722799987889604453348343072520573263;
    uint256 constant IC17y = 323757012091620534182876894477670570407871793557574147460713893009910871255;
    
    uint256 constant IC18x = 17683045070691608908867916226683809875435179131242263986889814596653301079427;
    uint256 constant IC18y = 10806926256774742030810353714672128083966649217025014214158182328487206381116;
    
    uint256 constant IC19x = 17900993080848976422371508787281519687273983434344270929059374760301472595875;
    uint256 constant IC19y = 11360901097483642997003325234245223468052969171555300190934461658699152454935;
    
    uint256 constant IC20x = 15073095730683863417193681852286966189586960779408249247512670812488037228103;
    uint256 constant IC20y = 10141206980613959523876191688183440767529954094847616455483787696689276587963;
    
    uint256 constant IC21x = 13712671622637839685738189155688984056459015865672692500839940078579226329481;
    uint256 constant IC21y = 11263144998534684143831541381843530656743041509385713218548756736652257658611;
    
    uint256 constant IC22x = 19380517006979116503310912059121274642389072814407546414061496467679945440505;
    uint256 constant IC22y = 15738869016665463193888499978929304107806764626529636910411292690645721799189;
    
    uint256 constant IC23x = 2509122510372404236811184825414694428485114256571742143018520477470415101095;
    uint256 constant IC23y = 17434976600125241758776020824789823803365450310931329507606234181530949793753;
    
    uint256 constant IC24x = 10138297647057393884786134633931773084554229067195710919497996384117172877632;
    uint256 constant IC24y = 11143695168425553823102948247823974909967053260227408722077356857929022922769;
    
    uint256 constant IC25x = 15504051032311972535257323871282327060802690666368481232681333465097978210142;
    uint256 constant IC25y = 312266604689764662907316606767539876543148288129712491166255110327390756976;
    
    uint256 constant IC26x = 19758810561250549960266167424712344519315340054552460966840682761461827163137;
    uint256 constant IC26y = 17768851710354104127227375704177333264625126990153181589692718285359244053297;
    
    uint256 constant IC27x = 17504223858318949872706981307573571475414961826570776086360533814510287305884;
    uint256 constant IC27y = 7318768548486263077325671774523363858180072040344410845009059744499063351150;
    
    uint256 constant IC28x = 2849161220900817413824276938067629180324694394204120898930328229315587308240;
    uint256 constant IC28y = 13384960849872345313999298925575957440937527075797993986743650836127229288277;
    
    uint256 constant IC29x = 18855663700284991485537331184521414326061859977950112135227537140966406601397;
    uint256 constant IC29y = 13934807610642582491829500542094634971098891637595426608586624835752967299182;
    
    uint256 constant IC30x = 17941235418599209730607996486501559167385689108246214253002087301175081078505;
    uint256 constant IC30y = 1426926098743027386507196854308222120824132286810539906716934129183174184574;
    
    uint256 constant IC31x = 19781968892169799339968070830883820266596455499244930794693207714257715835791;
    uint256 constant IC31y = 8306797640463228958340041707734597818207917913944084415692774600340032030244;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[31] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                
                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))
                
                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))
                
                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))
                
                g1_mulAccC(_pVk, IC28x, IC28y, calldataload(add(pubSignals, 864)))
                
                g1_mulAccC(_pVk, IC29x, IC29y, calldataload(add(pubSignals, 896)))
                
                g1_mulAccC(_pVk, IC30x, IC30y, calldataload(add(pubSignals, 928)))
                
                g1_mulAccC(_pVk, IC31x, IC31y, calldataload(add(pubSignals, 960)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            
            checkField(calldataload(add(_pubSignals, 736)))
            
            checkField(calldataload(add(_pubSignals, 768)))
            
            checkField(calldataload(add(_pubSignals, 800)))
            
            checkField(calldataload(add(_pubSignals, 832)))
            
            checkField(calldataload(add(_pubSignals, 864)))
            
            checkField(calldataload(add(_pubSignals, 896)))
            
            checkField(calldataload(add(_pubSignals, 928)))
            
            checkField(calldataload(add(_pubSignals, 960)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
