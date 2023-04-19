import fs from "fs";

import "hardhat-deploy";
import "@nomiclabs/hardhat-ethers";
import * as LitJsSdk from "@lit-protocol/lit-node-client";
import axios from "axios";
import { task } from "hardhat/config";
import { HardhatRuntimeEnvironment } from "hardhat/types";
import { SiweMessage } from "siwe";

import { PINATA_JWT } from "../../hardhat.config";

declare type ConditionType = "solRpc" | "evmBasic" | "evmContract" | "cosmos";

import { domain, getAllowListOffChainManagedContract } from "./utils";

const origin = "https://gnosis-auction.com";

const generateSignatures: () => void = () => {
  task(
    "generateSignatures",
    "Generates the signatures for the allowListManager",ion
  )
    .addParam("auctionId", "Id of the auction ")
    .addParam(
      "fileWithAddress",
      "File with comma separated addresses that should be allow-listed",
    )
    .addFlag(
      "postToApi",
      "Flag that indicates whether the signatures should be sent directly to the api",
    )
    .addFlag(
      "postToDevApi",
      "Flag that indicates whether the signatures should be sent directly to the api in development environment",
    )
    .setAction(async (taskArgs, hardhatRuntime) => {
      const [caller] = await hardhatRuntime.ethers.getSigners();
      console.log(
        "Using the account: ",
        caller.address,
        " to generate signatures",
      );

      // Loading dependencies
      const allowListContract = await getAllowListOffChainManagedContract(
        hardhatRuntime,
      );
      const { chainId } = await hardhatRuntime.ethers.provider.getNetwork();
      const contractDomain = domain(chainId, allowListContract.address);
      const litClient = new LitJsSdk.LitNodeClient({
        debug: true,
      });
      await litClient.connect();

      const authSig = await generateAuthSig(hardhatRuntime, taskArgs);

      // Creating signatures folder to store signatures:
      const dir = "./signatures";
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, {
          recursive: true,
        });
      }

      // Read signatures from provided file
      const file = fs.readFileSync(taskArgs.fileWithAddress, "utf8");
      const addresses = file.split(",").map((address) => address.trim());

      // Post signatures in packages of `signaturePackageSize` to the api and write
      // them into the file `signatures-ith.json`
      const signaturePackageSize = 10.0;
      for (let i = 0; i < addresses.length / signaturePackageSize; i++) {
        const signatures = [];
        console.log("Creating signatures for the ", i, "-th package");
        for (const address of addresses.slice(
          i * signaturePackageSize,
          (i + 1) * signaturePackageSize,
        )) {
          const auctioneerMessage = hardhatRuntime.ethers.utils.keccak256(
            hardhatRuntime.ethers.utils.defaultAbiCoder.encode(
              ["bytes32", "address", "uint256"],
              [
                hardhatRuntime.ethers.utils._TypedDataEncoder.hashDomain(
                  contractDomain,
                ),
                address,
                taskArgs.auctionId,
              ],
            ),
          );
          const auctioneerSignature = await caller.signMessage(
            hardhatRuntime.ethers.utils.arrayify(auctioneerMessage),
          );
          const sig = hardhatRuntime.ethers.utils.splitSignature(
            auctioneerSignature,
          );
          const auctioneerSignatureEncoded = hardhatRuntime.ethers.utils.defaultAbiCoder.encode(
            ["uint8", "bytes32", "bytes32"],
            [sig.v, sig.r, sig.s],
          );

          const {
            encryptedString,
            symmetricKey,
          } = await LitJsSdk.encryptString(auctioneerSignatureEncoded);

          const networkName = await getNetworkName(hardhatRuntime);

          const accessControlConditions = [
            {
              conditionType: "evmBasic" as ConditionType,
              contractAddress: "",
              standardContractType: "",
              chain: networkName,
              method: "",
              parameters: [":userAddress"],
              returnValueTest: {
                comparator: "=",
                value: address,
              },
            },
          ];

          const encryptedSymmetricKey = await litClient.saveEncryptionKey({
            accessControlConditions,
            symmetricKey,
            authSig,
            chain: networkName,
          });
          const data = JSON.stringify({
            pinataOptions: {
              cidVersion: 1,
            },
            pinataMetadata: {
              name: `${chainId}-${taskArgs.auctionId}-${address}`,
              keyvalues: {
                address,
                auctionId: taskArgs.auctionId,
              },
            },
            pinataContent: {
              encryptedString: await LitJsSdk.blobToBase64String(
                encryptedString,
              ),
              encryptedSymmetricKey: LitJsSdk.uint8arrayToString(
                encryptedSymmetricKey,
                "base16",
              ),
            },
          });

          await axios.post(
            "https://api.pinata.cloud/pinning/pinJSONToIPFS",
            data,
            {
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${PINATA_JWT}`,
              },
            },
          );

          signatures.push({
            user: address,
            signature: auctioneerSignatureEncoded,
          });
        }
        const json = JSON.stringify({
          auctionId: Number(taskArgs.auctionId),
          chainId: chainId,
          allowListContract: allowListContract.address,
          signatures: signatures,
        });

        // Writing signatures into file
        fs.writeFileSync(`signatures/signatures-${i}.json`, json, "utf8");
        console.log("Uploaded signatures to pinata cloud 🤩🥳");
      }
    });
};

interface AuthSig {
  sig: string;
  derivedVia: string;
  signedMessage: string;
  address: string;
}

async function generateAuthSig(
  hardhatRuntime: HardhatRuntimeEnvironment,
  taskArgs: any,
): Promise<AuthSig> {
  const networkInfo = await hardhatRuntime.ethers.provider.getNetwork();
  const [caller] = await hardhatRuntime.ethers.getSigners();

  const siweMessage = new SiweMessage({
    domain: "gnosis-auct",
    address: caller.address,
    statement: `Gnosis Auction ${taskArgs.auctionid}`,
    uri: origin,
    version: "1",
    chainId: networkInfo.chainId,
  });
  const messageToSign = siweMessage.prepareMessage();
  const signature = await caller.signMessage(messageToSign);
  const authSig = {
    sig: signature,
    derivedVia: "web3.eth.personal.sign",
    signedMessage: messageToSign,
    address: caller.address,
  };
  return authSig;
}

async function getNetworkName(
  hardhatRuntime: HardhatRuntimeEnvironment,
): Promise<string> {
  const networkInfo = await hardhatRuntime.ethers.provider.getNetwork();
  let networkName = networkInfo.name;
  if (networkInfo.chainId === 100) {
    networkName = "xdai";
  }
  if (networkInfo.chainId === 1) {
    networkName = "ethereum";
  }
  if (networkInfo.chainId === 137) {
    networkName = "polygon";
  }
  if (networkInfo.chainId === 5) {
    networkName = "goerli";
  }
  return networkName;
}
export { generateSignatures };
