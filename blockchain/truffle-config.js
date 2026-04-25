"use strict";

window.EVIDENCE_REGISTRY_CONFIG = Object.freeze({
    rpcUrl: "http://127.0.0.1:7545",
    contractAddress: "0xCD56b4Aa01F19E3041828259BccAFf9f91E230a7",
    abi: Object.freeze([
        {
            "inputs": [],
            "stateMutability": "nonpayable",
            "type": "constructor"
        },
        {
            "anonymous": false,
            "inputs": [
                {
                    "indexed": true,
                    "internalType": "uint256",
                    "name": "eventId",
                    "type": "uint256"
                },
                {
                    "indexed": true,
                    "internalType": "string",
                    "name": "deviceId",
                    "type": "string"
                },
                {
                    "indexed": false,
                    "internalType": "bool",
                    "name": "isLegitimate",
                    "type": "bool"
                },
                {
                    "indexed": false,
                    "internalType": "uint256",
                    "name": "timestamp",
                    "type": "uint256"
                },
                {
                    "indexed": true,
                    "internalType": "address",
                    "name": "reporter",
                    "type": "address"
                }
            ],
            "name": "NewEventLogged",
            "type": "event"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "_eventId",
                    "type": "uint256"
                }
            ],
            "name": "getEvent",
            "outputs": [
                {
                    "components": [
                        {
                            "internalType": "string",
                            "name": "deviceId",
                            "type": "string"
                        },
                        {
                            "internalType": "bool",
                            "name": "isLegitimate",
                            "type": "bool"
                        },
                        {
                            "internalType": "uint256",
                            "name": "timestamp",
                            "type": "uint256"
                        },
                        {
                            "internalType": "string",
                            "name": "details",
                            "type": "string"
                        },
                        {
                            "internalType": "address",
                            "name": "reporter",
                            "type": "address"
                        }
                    ],
                    "internalType": "struct EvidenceRegistry.AuthEvent",
                    "name": "",
                    "type": "tuple"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "getEventCount",
            "outputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "string",
                    "name": "_deviceId",
                    "type": "string"
                },
                {
                    "internalType": "bool",
                    "name": "_isLegitimate",
                    "type": "bool"
                },
                {
                    "internalType": "string",
                    "name": "_details",
                    "type": "string"
                }
            ],
            "name": "logEvent",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "owner",
            "outputs": [
                {
                    "internalType": "address",
                    "name": "",
                    "type": "address"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        }
    ])
});
