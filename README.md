# rld (Reflective DLL Loader)

`rld` is a Reflective DLL Loader written in Rust, designed to load and execute DLLs in a fileless manner. This loader operates in a `no_std` environment and uses specific hash values to obtain system API functions, enhancing the stealth of the binary.

## Table of Contents

- [Project Background](#project-background)
- [Features](#features)
- [Code Structure](#code-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)

## Project Background

Reflective DLL loading is a technique that allows you to map and execute a DLL in memory without using the standard Windows API function `LoadLibrary`. This technique is typically used to bypass traditional antivirus detection and file system monitoring, making it harder for malicious code to be detected.

This project implements a Reflective DLL Loader in Rust, leveraging the `no_std` environment to reduce dependency on the standard library, and using hash values to resolve function addresses, enhancing the loader's stealth.

## Features

- **Fileless Loading**: Directly loads and executes DLL binary data from memory.
- **Hash-Based Function Resolution**: Resolves system API functions using hash values to avoid exposing clear function names.
- **Custom Entrypoint**: Supports invoking exported functions of the DLL via hash values.
- **No Dependency Environment**: Operates in a `no_std` environment, with no dependency on the standard library.

## Code Structure

The main code files and modules in the project are as follows:

- `lib.rs`: The main file of the project, containing the core logic of the Reflective DLL Loader.
- `pe/`: A module for handling the PE file format, including functions for retrieving exports and loading modules.
- `macros/`: Macros used in the project to simplify code operations.
