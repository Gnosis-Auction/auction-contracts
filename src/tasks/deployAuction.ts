import "hardhat-deploy";
import "@nomiclabs/hardhat-ethers";
import { task } from "hardhat/config";

import { getWETH9Address, isAvaxNetwork } from "./utils";

const deployEasyAuctionContract: () => void = () => {
  task("deployEasyAuction", "Deploys the easyAuction contract").setAction(
    async (taskArgs, hardhatRuntime) => {
      const [caller] = await hardhatRuntime.ethers.getSigners();
      console.log("Using the account:", caller.address);
      const { deployments, getNamedAccounts } = hardhatRuntime;
      const { deployer } = await getNamedAccounts();
      const { deploy, get } = deployments;
      const chainId = (await hardhatRuntime.ethers.provider.getNetwork())
        .chainId;

      await deploy("EasyAuction", {
        from: deployer,
        gasLimit: 8000000,
        args: [],
        log: true,
        deterministicDeployment: false,
      });
      const easyAuctionDeployed = await get("EasyAuction");
      const weth9Address = await getWETH9Address(hardhatRuntime);

      await deploy("DepositAndPlaceOrder", {
        from: deployer,
        gasLimit: 8000000,
        args: [easyAuctionDeployed.address, weth9Address],
        log: true,
        deterministicDeployment: !isAvaxNetwork(chainId),
      });
    },
  );
};

export { deployEasyAuctionContract };
