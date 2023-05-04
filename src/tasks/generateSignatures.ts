import fs from "fs";

import "hardhat-deploy";
import "@nomiclabs/hardhat-ethers";
import axios from "axios";
import { task } from "hardhat/config";

import { PINATA_JWT } from "../../hardhat.config";

import { domain, getAllowListOffChainManagedContract } from "./utils";

const generateSignatures: () => void = () => {
  task(
    "generateSignatures",
    "Generates the signatures for the allowListManager",
  )
    .addParam("auctionId", "Id of the auction ")
    .addParam(
      "fileWithAddress",
      "File with comma separated addresses that should be allow-listed",
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
              signature: auctioneerSignatureEncoded,
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

export { generateSignatures };
