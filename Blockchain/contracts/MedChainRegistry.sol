// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MedChainRegistry {
    // Paziente = owner dei dati (msg.sender quando registra medico)
    // Medico = address autorizzato dal paziente

    struct Report {
        string deviceId;
        uint256 timestamp;        // epoch seconds
        bytes32 hashCiphertext;   // SHA-256 (in bytes32) del (ciphertext||tag) o equivalente
        uint256 offchainRef;      // id SQLite o ipfs pointer
        address patient;          // paziente proprietario del report
        address submittedBy;      // chi ha scritto il record on-chain (gateway)
    }

    uint256 public reportsCount;
    mapping(uint256 => Report) private reports;

    // patient => doctor => allowed
    mapping(address => mapping(address => bool)) public isDoctorAllowed;

    event AccessGranted(address indexed patient, address indexed doctor);
    event AccessRevoked(address indexed patient, address indexed doctor);

    event ReportRegistered(
        uint256 indexed reportId,
        address indexed patient,
        string deviceId,
        uint256 timestamp,
        bytes32 hashCiphertext,
        uint256 offchainRef,
        address indexed submittedBy
    );

    // Il paziente concede accesso a un medico
    function grantAccess(address doctor) external {
        require(doctor != address(0), "Doctor address zero");
        isDoctorAllowed[msg.sender][doctor] = true;
        emit AccessGranted(msg.sender, doctor);
    }

    // Il paziente revoca accesso
    function revokeAccess(address doctor) external {
        require(doctor != address(0), "Doctor address zero");
        isDoctorAllowed[msg.sender][doctor] = false;
        emit AccessRevoked(msg.sender, doctor);
    }

    /**
     * Registra report on-chain.
     * Nel prototipo puoi farlo chiamare dal gateway.
     * patient = address del paziente proprietario del dato.
     */
    function registerReport(
        address patient,
        string calldata deviceId,
        uint256 timestamp,
        bytes32 hashCiphertext,
        uint256 offchainRef
    ) external returns (uint256) {
        require(patient != address(0), "Patient address zero");
        require(bytes(deviceId).length > 0, "Empty deviceId");
        require(timestamp > 0, "Invalid timestamp");
        require(offchainRef > 0, "Invalid offchainRef");

        reportsCount += 1;

        reports[reportsCount] = Report({
            deviceId: deviceId,
            timestamp: timestamp,
            hashCiphertext: hashCiphertext,
            offchainRef: offchainRef,
            patient: patient,
            submittedBy: msg.sender
        });

        emit ReportRegistered(
            reportsCount,
            patient,
            deviceId,
            timestamp,
            hashCiphertext,
            offchainRef,
            msg.sender
        );

        return reportsCount;
    }

    // Lettura report: consentita al paziente o a un medico autorizzato da quel paziente
    function getReport(uint256 reportId)
        external
        view
        returns (
            address patient,
            string memory deviceId,
            uint256 timestamp,
            bytes32 hashCiphertext,
            uint256 offchainRef,
            address submittedBy
        )
    {
        Report storage r = reports[reportId];
        require(r.patient != address(0), "Report not found");

        bool canRead = (msg.sender == r.patient) || isDoctorAllowed[r.patient][msg.sender];
        require(canRead, "Not authorized");

        return (r.patient, r.deviceId, r.timestamp, r.hashCiphertext, r.offchainRef, r.submittedBy);
    }
}


