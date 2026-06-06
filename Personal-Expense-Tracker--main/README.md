# Cloud Migration and Cryptographic Hardening of Distributed Financial Ledger Systems

**Author:** Alex  
**University:** Amity University Online  
**Course:** BCA Final Year Project  
**Specialization Core:** Cloud & Security  

---

## Infrastructure Overview
An enterprise-grade, multi-user personal finance management infrastructure built on an advanced Python Tkinter framework. The architecture implements proper **Defense-in-Depth** principles by isolating core data-layer parameters within localized Environment Configurations (`.env`). 

User Identity and Access Management (IAM) is protected using adaptive work-factor cryptographic salting algorithms (`bcrypt`) to systematically mitigate offline dictionary attacks, rainbow tables, and credential-harvesting vulnerabilities. 

The underlying storage tier completely eliminates monolithic localized state data constraints by establishing an asymmetric network pipeline to a globally reachable distributed **MongoDB Atlas Cloud Cluster** hosted on AWS nodes.

---

## Key Core Features
* **Distributed Cloud Architecture:** Live document tracking managed over remote database clusters with automatic regional scaling.
* **Bcrypt Identity Protection:** High-security cryptographic password stretching with automated random salt generation (12 routing work factors).
* **Data Layer Isolation:** Environment configuration variable abstraction to prevent structural network string exposure within the public code repository.
* **Server-Side Data Aggregation:** Native NoSQL data pipelines aggregate spending volatility trends seamlessly across cloud database shards.
* **Real-Time Visual Diagnostics:** Interactive data tracking engines powered by Matplotlib to render live volumetric spending distributions.
* **System Portability:** Integrated file system tools to generate clean spreadsheet parsing data exports via structural CSV mapping layouts.

---

## Pre-Requisites & Requirements
The underlying runtime engine relies on modern external drivers to handle remote connection security protocols. Execute the bootstrap tool installation sequence via your terminal shell:

```cmd
pip install pymongo bcrypt python-dotenv matplotlib