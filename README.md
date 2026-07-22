## MEGACART ATTACK DETECTION SYSTEM

## About the project
MADS scans all JavaScript files loaded on a webpage and checks each one against two criteria:

> Is the script whitelisted?
> Is its Subresource Integrity (SRI) hash valid?

If both checks pass → the script is marked safe and runs normally, while taint tracking stays active in the background.

If either check fails → the script is flagged as suspicious, and taint tracking determines whether card data is being sent to an external destination:

No suspicious data flow → the script is flagged for review.
Suspicious data flow detected → the script is blocked immediately, the incident is logged, and the admin is alerted.

## 📸 UI Screenshots

> Screenshots of the admin interface including the Dashboard, Script Monitor, Incident Log, CSP Config, and Report Generator are available in the /docs/screenshots/ folder.

-----

## 📚 Background & Research

This project was built in response to the growing threat of Magecart-style supply chain attacks, which have compromised major e-commerce platforms worldwide.

It specifically addresses a gap in client-side security tooling for small and medium-sized e-commerce businesses in emerging markets like Kenya, where digital commerce is expanding quickly but cybersecurity infrastructure often lags behind.

# Key concepts applied:

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
