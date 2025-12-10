// SPDX-License-Identifier: MIT 

pragma solidity ^0.8.20;

contract MedChainRegistry{
    struct Report{
        string deviceId;
        uint256 timestamp;
        bytes32 hashCiphertext;
        uint256 offchainRef;
        string hmac;
        address submittedBy;
    }

    mapping(uint256=> Report) private reports;
    uint256 public reportsCount;

    event ReportRegistered(
        uint256 indexed reportId,
        string deviceId,
        uint256 timestamp,
        bytes32 hashCiphertext,
        uint256 offchainRef,
        address indexed submittedBy
    );

    function registerReport(
        string memory deviceId,
        uint256 timestamp,
        bytes32 hashCiphertext,
        uint256 offchainRef,
        string memory hmacFirma
    ) external returns (uint256) {
        require(bytes(deviceId).length > 0, "DeviceId vuoto");
        require(timestamp > 0, "Timestamp non valido");
        require(offchainRef > 0, "OffchainRef non valido");

        reportsCount +=1;

        reports[reportsCount]=Report({
            deviceId: deviceId,
            timestamp: timestamp,
            hashCiphertext: hashCiphertext,
            offchainRef: offchainRef,
            hmac: hmacFirma,
            submittedBy: msg.sender
        });

        emit ReportRegistered(
            reportsCount,
            deviceId,
            timestamp,
            hashCiphertext,
            offchainRef,
            msg.sender
        );

        return reportsCount;
    }

    function getReport(uint256 reportId)
        external
        view
        returns(
            string memory deviceId,
            uint256 timestamp,
            bytes32 hashCiphertext,
            uint256 offchainRef,
            string memory hmac,
            address submittedBy
        )
    {
        Report storage r= reports[reportId];
        require(bytes(r.deviceId).length>0, "Report insesistente");

        return(
            r.deviceId,
            r.timestamp,
            r.hashCiphertext,
            r.offchainRef,
            r.hmac,
            r.submittedBy
        );
    }

}

