#MEGACART ATTACK DETECTION SYSTEM

#About the project
MADS scans all loaded JavaScript files
        ↓
Each script checked → Is it whitelisted? Is SRI hash valid?
        ↓                              ↓
      ✅ Safe                    ❌ Suspicious
   Script runs                Taint tracking activated
   normally                         ↓
                         Is card data being sent externally?
                              ↓                ↓
                           ✅ No            🚨 Yes
                        Flag for review   BLOCK script
                                          Log incident
                                          Alert admin

-----

## 📸 UI Screenshots

> Screenshots of the admin interface including the Dashboard, Script Monitor, Incident Log, CSP Config, and Report Generator are available in the /docs/screenshots/ folder.

-----

## 📚 Background & Research

This project was developed in response to the growing threat of Magecart-style supply chain attacks, which have affected thousands of e-commerce platforms globally including British Airways, Ticketmaster, and Newegg.

The system specifically targets the gap in client-side security tools available to SMEs in emerging markets like Kenya, where digital commerce is growing rapidly but cybersecurity infrastructure remains limited.

Key concepts applied:

- 🔑 Subresource Integrity (SRI)
- 🛡️ Content Security Policy (CSP)
- 🧬 Abstract Syntax Tree (AST) analysis
- 🔍 Taint Tracking
- 🏗️ Supply Chain Attack mitigation

-----

## 👩‍💻 Author

Charity — Diploma in Cybersecurity and Forensics Student  
📍 Zetech University, Kenya  
🔗 [GitHub](https://github.com/PANUELS)

-----

## 📄 License

This project was developed for academic purposes as part of a diploma final year project at Zetech University. All rights reserved.

-----

> *“Security is not a product, but a process.”* — Bruce Schneier
