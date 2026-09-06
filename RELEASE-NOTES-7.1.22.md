# Generátor testů 7.1.22 – Platform 1.1.2 Studio manifest alignment

Patch pro koordinovanou GHRAB Platform 1.1.2 release wave.

- Zdrojová šablona `studio/app-manifest.template.json` nyní deklaruje přesně Platformu `1.1.2` a `>=1.1.2 <2.0.0`.
- Runtime vendor, consumer manifest, suite-session cleanup a PC-01 ownership se funkčně nemění; již byly na Platformě 1.1.2.
- Oprava zabraňuje tomu, aby AI Studio při source-repository fallbacku převzalo zastaralou deklaraci Platformy 1.0.0.
- Kandidát zůstává neprodukční do společného ověření celé release wave.
