# Generátor testů 7.1.23 — GARP 2.5.1 SHIELD-PREP source candidate

Datum: 2026-09-07

## Co se změnilo
- zavedena GARP 2.5.1 TOOLING-R2 vrstva do `security/garp25/tools`;
- přidán autoritativní `security/security-critical-assets.json` pro fail-closed SW release gate;
- GARP selftest/SBOM/SW-freeze/deployment-leak kontroly jsou zapojeny do hlavních testovacích řetězců po buildu;
- přidán CycloneDX 1.7 SBOM a deterministický SBOM drift check;
- build podporuje `GHRAB_BUILD_TIME` pro reprodukovatelný timestamp; bez proměnné funguje jako dříve;
- doplněn threat model, attack surface, deployment security profil, AI resource budget, crosswalk, právní inventář binárních assetů, key-custody a release-integrity postup.

## Security-boundary diff proti předanému 7.1.22 snapshotu
- distribuovaný runtime: ANO — kromě release/version/cache/build metadat se mění i service-worker routing: security-critical assety jsou explicitně vyjmuty z cache-first a jdou přes network-only/no-store fail-closed větev; aplikační AI logika se nemění;
- prompt assembly/system prompt/provider/model: NE;
- auth/app-guard/session: ANO v distribuční/freshness hranici service workeru (nikoli v samotné autorizační, podpisové ani session business logice); session cleanup, platform guard a release-integrity cesty jsou nyní explicitně network-only/no-store;
- storage/import/export/data flow: NE;
- AI tool/MCP/agent scope: ANO v klasifikaci/dokumentaci — Gemini `url_context` je explicitně veden jako omezená provider-side schopnost, proto AGENTIC=PARTIAL; nevzniká lokální agentická smyčka ani nové aplikační side effects;
- network egress: NE.

## Ověření v tomto prostředí
- GARP 2.3 structural security harness: PASS 86/86;
- suite-session lifecycle: PASS 20/20;
- verze/actions/production invariants/source structure/sensitive sweep/deadline timers/studio manifest: PASS;
- GARP 2.5.1 tooling selftest po opravném kole: PASS 47/47;
- CycloneDX 1.7 SBOM generation/drift/quality: PASS, 113 komponent, 113 unikátních purl, 113 lockfile hashů.

## Opravné kolo po nezávislém auditu – kolo 1
- N-01: deployment leak scanner zpřesněn; legitimní `token: ` konkatenace PASS, skutečné syntetické přiřazení tokenu FAIL.
- N-02/N2-02: AI assurance fingerprint rozšířen na 16 souborů a doplněn automatickou kontrolou rozsahu: nový src soubor s AI/prompt-boundary tokenem musí být explicitně sledován. Per-file mutační kontroly se provádějí pro všech 16 souborů.
- N-03: opraveny názvy/purl/hash v CycloneDX SBOM a přidána kvalitativní validace.
- N-04: `GHRAB_BUILD_TIME` sjednocen i do platformního a school-profile postprocessingu.
- N-05: doplněn `verify-assurance-links.mjs`; release gate už krok nemůže tiše přeskočit.
- N-06: `url_context` deklarován v registru operací a AGENTIC profil opraven na PARTIAL; threat model zachycuje oslabení `responseMimeType`.
- N-07: AI Core synchronizace používá cílené přepisování klíčů; `brandVersion` je chráněna regresním testem.
- N-09/N-10: robustnější Chromium resolver a odstraněna dvě lint varování.
- GH-01/N2-03: vendored-consistency deklaruje public, dist i podporovaný dist-school-server profil. Interní konzistence je oddělena od cross-repo kanonické shody, která zůstává NOT TESTED bez repozitáře AI-Studio-GHRAB.


## Co není tvrzeno jako PASS
`npm ci` s přesně uzamčenými závislostmi, plný headless/axe řetězec a served LIVE/DAST. V tomto opravném prostředí zůstává registry DNS nedostupné. Pro lokální ověření buildové deterministiky byl dočasně použit pouze build-time Acorn 8.15.0 z předinstalovaného toolingu místo lockfile Acorn 8.17.0; `node_modules` se do kandidáta nebalí a tento surrogate build není vydáván za přesný release build. Browser testy závislé na lokálním Chromium jsou navíc částečně omezeny spravovanou URLBlocklist politikou. SHIELD-LIVE a RI-LIVE zůstávají NOT TESTED.

Tato verze je kandidát pro nezávislé Prompt E review, nikoli produkční release.

## Opravné kolo 3
- N2-01: leak scanner zachovává anti-concatenation lookahead a znovu pokrývá širokou třídu speciálních znaků v heslech/secretech.
- N2-02: 16-file AI fingerprint + automatická scope coverage kontrola.
- N2-03: deklarovány public a school-server kopie vendored artefaktů; build:school-server spouští stejnou konzistenční bránu.
- Aplikační runtime/business logika nebyla změněna.
