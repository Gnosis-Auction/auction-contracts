import "hardhat-deploy";
import "@nomiclabs/hardhat-ethers";
import { task } from "hardhat/config";

import { isAvaxNetwork } from "./utils";

const deployVerifier: () => void = () => {
  task("deployVerifier", "Deploy Verifier contract").setAction(
    async (taskArgs, hardhatRuntime) => {
      const [caller] = await hardhatRuntime.ethers.getSigners();
      console.log("Using the account:", caller.address);
      const { deployments, getNamedAccounts } = hardhatRuntime;
      const { deployer } = await getNamedAccounts();
      const { deploy, get } = deployments;
      const chainId = (await hardhatRuntime.ethers.provider.getNetwork())
        .chainId;

      await deploy("AllowListOffChainManaged", {
        from: deployer,
        gasLimit: 8000000,
        args: [],
        log: true,
        deterministicDeployment: !isAvaxNetwork(chainId),
      });
    },
  );
};

export { deployVerifier };
