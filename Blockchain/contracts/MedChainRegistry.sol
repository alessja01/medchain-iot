// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MedChainRegistry {
    // =========================
    // ADMIN / OWNER
    // =========================
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    // =========================
    // GATEWAY ALLOWLIST
    // =========================
    mapping(address => bool) public trustedGateway;

    event GatewayAuthorized(address indexed gateway);
    event GatewayRevoked(address indexed gateway);

    // =========================
    // DEVICE REGISTRY
    // =========================
    mapping(bytes32 => bool) public deviceAuthorized;

    event DeviceAuthorized(bytes32 indexed deviceIdHash);
    event DeviceRevoked(bytes32 indexed deviceIdHash);

    // =========================
    // ACCESS CONTROL PAZIENTE -> MEDICO
    // =========================
    mapping(address => mapping(address => bool)) public isDoctorAllowed;

    event AccessGranted(address indexed patient, address indexed doctor);
    event AccessRevoked(address indexed patient, address indexed doctor);

    // =========================
    // REPORT STORAGE + ANTI-REPLAY
    // =========================
    struct Report {
        bytes32 deviceIdHash;
        uint256 timestamp;
        bytes32 hashCiphertext;
        uint256 offchainRef;
        address patient;
        address submittedBy;

        // ✅ NUOVO: hash della firma del gateway sul canonical REPORT
        // (es. keccak256(signatureEd25519HexBytes))
        bytes32 gatewaySigHash;
    }

    uint256 public reportsCount;
    mapping(uint256 => Report) private reports;

    // anti-duplicati sul blob cifrato
    mapping(bytes32 => bool) public usedHash;

    event ReportRegistered(
        uint256 indexed reportId,
        address indexed patient,
        bytes32 indexed deviceIdHash,
        uint256 timestamp,
        bytes32 hashCiphertext,
        uint256 offchainRef,
        address submittedBy,
        bytes32 gatewaySigHash // ✅ NUOVO
    );

    event ReportAccessed(uint256 indexed reportId, address indexed accessor);

    // =========================
    // CONSTRUCTOR
    // =========================
    constructor() {
        owner = msg.sender;

        // bootstrap: owner è gateway fidato
        trustedGateway[msg.sender] = true;
        emit GatewayAuthorized(msg.sender);
    }

    // =========================
    // OWNER MANAGEMENT
    // =========================
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Owner zero");
        owner = newOwner;
    }

    // =========================
    // GATEWAY MANAGEMENT
    // =========================
    function authorizeGateway(address gateway) external onlyOwner {
        require(gateway != address(0), "Gateway zero");
        trustedGateway[gateway] = true;
        emit GatewayAuthorized(gateway);
    }

    function revokeGateway(address gateway) external onlyOwner {
        require(gateway != address(0), "Gateway zero");
        trustedGateway[gateway] = false;
        emit GatewayRevoked(gateway);
    }

    // =========================
    // DEVICE MANAGEMENT
    // =========================
    function authorizeDevice(bytes32 deviceIdHash) external onlyOwner {
        require(deviceIdHash != bytes32(0), "deviceIdHash zero");
        deviceAuthorized[deviceIdHash] = true;
        emit DeviceAuthorized(deviceIdHash);
    }

    function revokeDevice(bytes32 deviceIdHash) external onlyOwner {
        require(deviceIdHash != bytes32(0), "deviceIdHash zero");
        deviceAuthorized[deviceIdHash] = false;
        emit DeviceRevoked(deviceIdHash);
    }

    // =========================
    // PAZIENTE -> MEDICO ACL
    // =========================
    function grantAccess(address doctor) external {
        require(doctor != address(0), "Doctor zero");
        isDoctorAllowed[msg.sender][doctor] = true;
        emit AccessGranted(msg.sender, doctor);
    }

    function revokeAccess(address doctor) external {
        require(doctor != address(0), "Doctor zero");
        isDoctorAllowed[msg.sender][doctor] = false;
        emit AccessRevoked(msg.sender, doctor);
    }

    // =========================
    // REPORT REGISTRATION
    // =========================
    function registerReport(
        address patient,
        bytes32 deviceIdHash,
        uint256 timestamp,
        bytes32 hashCiphertext,
        uint256 offchainRef,
        bytes32 gatewaySigHash // ✅ NUOVO parametro
    ) external returns (uint256) {
        // 1) Solo gateway autorizzato
        require(trustedGateway[msg.sender], "Untrusted gateway");

        // 2) Check input
        require(patient != address(0), "Patient zero");
        require(deviceIdHash != bytes32(0), "deviceIdHash zero");
        require(deviceAuthorized[deviceIdHash], "Device not authorized");
        require(timestamp > 0, "Invalid timestamp");
        require(hashCiphertext != bytes32(0), "Invalid hash");
        require(offchainRef > 0, "Invalid offchainRef");
        require(gatewaySigHash != bytes32(0), "Invalid gatewaySigHash"); // ✅

        // 3) Anti-replay: stesso hash non può essere registrato due volte
        require(!usedHash[hashCiphertext], "Duplicate report");
        usedHash[hashCiphertext] = true;

        // 4) Salvataggio
        reportsCount += 1;

        reports[reportsCount] = Report({
            deviceIdHash: deviceIdHash,
            timestamp: timestamp,
            hashCiphertext: hashCiphertext,
            offchainRef: offchainRef,
            patient: patient,
            submittedBy: msg.sender,
            gatewaySigHash: gatewaySigHash
        });

        // 5) Evento
        emit ReportRegistered(
            reportsCount,
            patient,
            deviceIdHash,
            timestamp,
            hashCiphertext,
            offchainRef,
            msg.sender,
            gatewaySigHash
        );

        return reportsCount;
    }

    // =========================
    // READ (senza audit)
    // =========================
    function getReport(uint256 reportId)
        external
        view
        returns (
            address patient,
            bytes32 deviceIdHash,
            uint256 timestamp,
            bytes32 hashCiphertext,
            uint256 offchainRef,
            address submittedBy,
            bytes32 gatewaySigHash // ✅ NUOVO
        )
    {
        Report storage r = reports[reportId];
        require(r.patient != address(0), "Report not found");

        bool canRead = (msg.sender == r.patient) || isDoctorAllowed[r.patient][msg.sender];
        require(canRead, "Not authorized");

        return (
            r.patient,
            r.deviceIdHash,
            r.timestamp,
            r.hashCiphertext,
            r.offchainRef,
            r.submittedBy,
            r.gatewaySigHash
        );
    }

    // =========================
    // READ (con audit)
    // =========================
    function accessReport(uint256 reportId)
        external
        returns (
            address patient,
            bytes32 deviceIdHash,
            uint256 timestamp,
            bytes32 hashCiphertext,
            uint256 offchainRef,
            address submittedBy,
            bytes32 gatewaySigHash // ✅ NUOVO
        )
    {
        Report storage r = reports[reportId];
        require(r.patient != address(0), "Report not found");

        bool canRead = (msg.sender == r.patient) || isDoctorAllowed[r.patient][msg.sender];
        require(canRead, "Not authorized");

        emit ReportAccessed(reportId, msg.sender);

        return (
            r.patient,
            r.deviceIdHash,
            r.timestamp,
            r.hashCiphertext,
            r.offchainRef,
            r.submittedBy,
            r.gatewaySigHash
        );
    }
}
