const hre= require("hardhat");


// Script demo per mostrare funzionalità base del contratto MedChainRegistry

async function main(params) {
    //gateway: dispositivo che registra i report
    //patient: paziente a cui appartengono i report
    //doctor: medico che può accedere ai report del paziente
    const [gateway,patient,doctor]= await hre.ethers.getSigners(); //restituisce una lista di account pronti 

    //Indirizzo del contratto MedChainRegistry
    const CONTRACT= process.env.CONTRACT;

    //Se il contratto è vuoto, lo script non può sapere dove sta il contratto
    if (!CONTRACT) throw new Error("Metti CONTRACT= 0x... prima di lanciare lo script");

    //permette di collegare il contratto già deployato => registry diventa un oggetto JS 
    const registry= await hre.ethers.getContractAt("MedChainRegistry",CONTRACT);

    //serve solo pe vedere chi è chi
    console.log("Gateway:", gateway.address);
    console.log("Patient:", patient.address);
    console.log("Doctor:", doctor.address);

    //1) Paziente concede accesso al medico
    await (await registry.connect(patient).grantAccess(doctor.address)).wait();
    console.log("Accesso concesso al medico");

    //2) Gateway registra report per quel paziente
    const deviceId= "esp32-001";
    const timestamp= Math.floor(Date.now()/1000);
    const hashCiphertext= "0x" + "11".repeat(32); //byte32 di esempio

    const tx= await registry.connect(gateway).registerReport(
        patient.address,
        deviceId,
        timestamp,
        hashCiphertext
    );
    const receipt= await tx.wait();
    console.log("Report registrato in block:", receipt.hash);

    //3) Medico recupera report del paziente
    const reports= await registry.connect(doctor).getReports(patient.address);
    console.log("Report del paziente:", reports);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});