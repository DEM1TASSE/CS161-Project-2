# CS161 Project 2: An End-to-End Encrypted File Sharing System

![Project Status](https://img.shields.io/badge/Project%20Status-Completed-success.svg)

This repository contains my work for CS161 Project 2 at UC Berkeley, Spring 2023.

## Project Description
The project implements an end-to-end encrypted file sharing system, supporting user authentication, secure file storage, efficient file appending, and secure file sharing with controlled access and revocation. Users can securely upload, download, and share files while ensuring confidentiality, integrity, and access control.

For comprehensive documentation, see the [Project 2 Spec](https://sp23.cs161.org/proj2/).

## Implementation Details
My implementation code can be found in the following files: 

- `client/client.go`: Main implementation of the end-to-end encrypted file sharing system.
- `client_test/client_test.go`: Test cases to validate the implemented functionalities.

## Testing
To test my implementation, run the following command inside the `client_test` directory:   

```bash
go test -v
```  

Thank you for checking out my project!
