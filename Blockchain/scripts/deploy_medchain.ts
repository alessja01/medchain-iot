import hre from "hardhat";
import { writeFileSync, mkdirSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";

// ✅ __dirname in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main() {
  const MedChainRegistry = await hre.ethers.getContractFactory("MedChainRegistry");
  const medchain = await MedChainRegistry.deploy();
  await medchain.waitForDeployment();

  const address = await medchain.getAddress();
  console.log("✅ MedChainRegistry deployed to:", address);

  // ✅ salva deployments/local.json
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  mkdirSync(deploymentsDir, { recursive: true });

  const outPath = path.join(deploymentsDir, "local.json");
  writeFileSync(
    outPath,
    JSON.stringify(
      {
        MedChainRegistry: {
          address,
          network: "localhost",
          chainId: 31337
        }
      },
      null,
      2
    )
  );

  console.log("📝 Deployment salvato in:", outPath);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
