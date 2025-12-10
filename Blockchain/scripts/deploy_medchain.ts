const hre = require("hardhat");

async function main() {
  const MedChainRegistry = await hre.ethers.getContractFactory("MedChainRegistry");
  const registry = await MedChainRegistry.deploy();

  await registry.waitForDeployment();

  console.log("MedChainRegistry deployed to:", registry.target);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
