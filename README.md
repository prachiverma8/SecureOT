# SecureOT – Privacy-Preserving Data Transfer System

## Introduction

SecureOT is a Python-based web application that demonstrates privacy-preserving data transfer using Oblivious Transfer (OT) and IKNP OT Extension.

The system allows a sender to provide two messages while the receiver selects and obtains only one of them. The sender does not learn which message was selected by the receiver.

The project implements a basic 1-out-of-2 Oblivious Transfer protocol and an educational implementation of IKNP OT Extension to demonstrate how multiple transfers can be performed using a smaller set of base OTs.

## Objectives

- Understand the working of 1-out-of-2 Oblivious Transfer.
- Implement a basic OT protocol using Diffie-Hellman key exchange.
- Demonstrate IKNP OT Extension.
- Provide a web interface for sender and receiver operations.
- Compare the execution time of Basic OT and IKNP OT Extension.

## Features

- Sender and receiver interfaces.
- 1-out-of-2 Oblivious Transfer.
- Diffie-Hellman-based key exchange.
- SHA-256-based key derivation.
- AES-GCM encryption and decryption.
- Educational IKNP OT Extension implementation.
- Protocol visualization.
- Performance comparison dashboard.
- Graphical representation of execution time.

## Technologies Used

**Programming Language:** Python

**Web Framework:** Flask

**Cryptographic Libraries:** Cryptography

**Other Libraries:** NumPy, Matplotlib

**Frontend:** HTML, CSS, JavaScript

## Project Structure

```text
SecureOT/
│
├── app.py
├── ot_protocol.py
├── iknp.py
├── performance.py
├── requirements.txt
├── README.md
│
├── static/
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   └── script.js
│   └── graphs/
│
└── templates/
    ├── index.html
    ├── sender.html
    ├── receiver.html
    ├── visualization.html
    ├── performance.html
    └── iknp.html
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/prachiverma8/SecureOT.git
```

### 2. Open the project directory

```bash
cd SecureOT
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

### 4. Activate the virtual environment

For Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

### 5. Install the required dependencies

```bash
pip install -r requirements.txt
```

### 6. Run the application

```bash
python app.py
```

Open the following address in your browser:

```text
http://127.0.0.1:5000
```

## Performance Evaluation

The project compares Basic OT and IKNP OT Extension for different numbers of message transfers.

The performance dashboard displays:

- Basic OT execution time.
- Base OT setup time.
- OT Extension execution time.
- Total IKNP execution time.
- Performance comparison graph.

The measurements demonstrate the cost of base OT initialization and the execution time of the extension phase.

In the current implementation, base OT setup is repeated for each batch. Therefore, the setup cost dominates the total IKNP execution time. Reusing base OT results across multiple batches could help demonstrate the amortized performance benefit of OT Extension.

## Limitations

- This is an educational prototype developed to demonstrate cryptographic concepts.
- The implementation has not undergone formal security auditing.
- The application uses in-memory storage for demonstration purposes.
- Performance measurements are dependent on the local system and execution environment.
- The implementation should not be used for real-world sensitive data transfers.

## Future Scope

- Improve the implementation of OT Extension.
- Reuse base OT results across multiple transfer batches.
- Improve the application's security and session management.
- Add support for larger message transfers.
- Conduct more extensive performance evaluations.

## Conclusion

SecureOT demonstrates the concepts of Oblivious Transfer and IKNP OT Extension through a web-based application. It provides an interactive way to understand privacy-preserving data transfer and evaluate the performance of the implemented protocols.

## Author

**Prachi Verma**

B.Tech – Computer Science and Engineering

Indira Gandhi Delhi Technical University for Women