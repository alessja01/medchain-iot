// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MedChainRegistry {
    // =========================
    // ADMIN / OWNER
    // =========================

    // Account amministratore (ospedale / admin di sistema)
    address public owner;

    // Modifier: permette l’esecuzione solo all’owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    // =========================
    // GATEWAY ALLOWLIST
    // =========================

    // Solo questi indirizzi possono registrare report
    mapping(address => bool) public trustedGateway;

    event GatewayAuthorized(address indexed gateway);
    event GatewayRevoked(address indexed gateway);

    // =========================
    // DEVICE REGISTRY
    // =========================

    /**
     * deviceIdHash = keccak256(bytes(deviceIdString))
     * Esempio: deviceIdString = "esp32-001"
     * deviceIdHash è bytes32, più economico della stringa su chain.
     */
    mapping(bytes32 => bool) public deviceAuthorized;

    event DeviceAuthorized(bytes32 indexed deviceIdHash);
    event DeviceRevoked(bytes32 indexed deviceIdHash);

    // =========================
    // ACCESS CONTROL PAZIENTE -> MEDICO
    // =========================

    // patient => doctor => allowed
    mapping(address => mapping(address => bool)) public isDoctorAllowed;

    event AccessGranted(address indexed patient, address indexed doctor);
    event AccessRevoked(address indexed patient, address indexed doctor);

    // =========================
    // REPORT STORAGE + ANTI-REPLAY
    // =========================

    struct Report {
        bytes32 deviceIdHash;     // ID device (hash)
        uint256 timestamp;        // epoch seconds
        bytes32 hashCiphertext;   // hash del blob cifrato (consiglio: nonce||ciphertext||tag)
        uint256 offchainRef;      // riferimento off-chain (id SQLite)
        address patient;          // paziente owner dei dati
        address submittedBy;      // gateway che ha registrato (msg.sender)
    }

    // contatore report
    uint256 public reportsCount;

    // mapping reportId -> hint metadati report
    mapping(uint256 => Report) private reports;

    // Anti-duplicati: impedisce di registrare lo stesso hash più volte
    mapping(bytes32 => bool) public usedHash;

    event ReportRegistered(
        uint256 indexed reportId,
        address indexed patient,
        bytes32 indexed deviceIdHash,
        uint256 timestamp,
        bytes32 hashCiphertext,
        uint256 offchainRef,
        address submittedBy
    );

    // Evento audit quando qualcuno accede a un report tramite accessReport()
    event ReportAccessed(uint256 indexed reportId, address indexed accessor);

    // =========================
    // CONSTRUCTOR
    // =========================

    constructor() {
        // chi deploya il contratto diventa owner
        owner = msg.sender;

        // bootstrap: l’owner è considerato gateway fidato
        trustedGateway[msg.sender] = true;
        emit GatewayAuthorized(msg.sender);
    }

    // =========================
    // OWNER MANAGEMENT
    // =========================

    // Cambia owner (es. passaggio da account #0 a un multisig)
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Owner zero");
        owner = newOwner;
    }

    // =========================
    // GATEWAY MANAGEMENT
    // =========================

    // Autorizza un gateway a registrare report
    function authorizeGateway(address gateway) external onlyOwner {
        require(gateway != address(0), "Gateway zero");
        trustedGateway[gateway] = true;
        emit GatewayAuthorized(gateway);
    }

    // Revoca un gateway (non potrà più registrare report)
    function revokeGateway(address gateway) external onlyOwner {
        require(gateway != address(0), "Gateway zero");
        trustedGateway[gateway] = false;
        emit GatewayRevoked(gateway);
    }

    // =========================
    // DEVICE MANAGEMENT
    // =========================

    // Autorizza un device (deviceIdHash)
    function authorizeDevice(bytes32 deviceIdHash) external onlyOwner {
        require(deviceIdHash != bytes32(0), "deviceIdHash zero");
        deviceAuthorized[deviceIdHash] = true;
        emit DeviceAuthorized(deviceIdHash);
    }

    // Revoca un device (es. compromesso)
    function revokeDevice(bytes32 deviceIdHash) external onlyOwner {
        require(deviceIdHash != bytes32(0), "deviceIdHash zero");
        deviceAuthorized[deviceIdHash] = false;
        emit DeviceRevoked(deviceIdHash);
    }

    // =========================
    // PAZIENTE -> MEDICO ACL
    // =========================

    // Il paziente concede accesso a un medico
    function grantAccess(address doctor) external {
        require(doctor != address(0), "Doctor zero");
        isDoctorAllowed[msg.sender][doctor] = true;
        emit AccessGranted(msg.sender, doctor);
    }

    // Il paziente revoca accesso
    function revokeAccess(address doctor) external {
        require(doctor != address(0), "Doctor zero");
        isDoctorAllowed[msg.sender][doctor] = false;
        emit AccessRevoked(msg.sender, doctor);
    }

    // =========================
    // REPORT REGISTRATION
    // =========================

    /**
     * registerReport:
     * - solo gateway fidato può chiamarla
     * - device deve essere autorizzato
     * - hash non deve essere duplicato (anti-replay)
     * - salva metadati e emette evento
     */
    function registerReport(
        address patient,
        bytes32 deviceIdHash,
        uint256 timestamp,
        bytes32 hashCiphertext,
        uint256 offchainRef
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
            submittedBy: msg.sender
        });

        // 5) Evento per indicare che il report è stato registrato
        emit ReportRegistered(
            reportsCount,
            patient,
            deviceIdHash,
            timestamp,
            hashCiphertext,
            offchainRef,
            msg.sender
        );

        return reportsCount;
    }

    // =========================
    // READ (senza audit)
    // =========================

    /**
     * getReport:
     * - è view: non costa gas
     * - NON può emettere evento di audit
     * - accesso consentito a paziente o medico autorizzato
     */
    function getReport(uint256 reportId)
        external
        view
        returns (
            address patient,
            bytes32 deviceIdHash,
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

        return (r.patient, r.deviceIdHash, r.timestamp, r.hashCiphertext, r.offchainRef, r.submittedBy);
    }

    // =========================
    // READ (con audit)
    // =========================

    /**
     * accessReport:
     * - NON è view: costa gas
     * - emette ReportAccessed per audit trail
     * - restituisce gli stessi dati di getReport
     */
    function accessReport(uint256 reportId)
        external
        returns (
            address patient,
            bytes32 deviceIdHash,
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

        emit ReportAccessed(reportId, msg.sender);

        return (r.patient, r.deviceIdHash, r.timestamp, r.hashCiphertext, r.offchainRef, r.submittedBy);
    }
}


