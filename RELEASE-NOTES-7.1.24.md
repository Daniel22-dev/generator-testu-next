# Generátor testů 7.1.24 — GARP 2.5.1 runtime hardening po nezávislém Kole 3

## Účel
Tato verze reaguje na nález N3-01 z nezávislého auditu 7.1.23. Nemění business logiku generátoru, AI prompt assembly ani datový model. Jediná zamýšlená runtime změna je politika Service Workeru pro dvě freshness-sensitive podpůrné vrstvy.

## N3-01 — offline dostupnost cleanup/platform vrstvy
- `access/suite-session-cleanup.js` a `ghrab/ghrab-platform.js` jsou explicitně `networkFirst` s `cache: no-store` pokusem a cache fallbackem.
- Obě vrstvy jsou součástí install precache, takže poslední známá verze je dostupná i bez sítě.
- Autorizační, revokační a integrity artefakty zůstávají `networkOnlyNoStore` bez cache fallbacku.
- Bezpečnostní policy je rozdělena na `networkOnly` a `networkFirstFallback`.
- Přidán regresní test offline směrování, který zároveň ověřuje, že revokace se z cache nikdy nepoužije.

## N3-02 — rozsah AI fingerprintu
- Scope discovery prochází `src/` i `public/`, přípony `.js` i `.mjs`.
- Sleduje i přímé Gemini transportní tokeny `generativelanguage.googleapis.com` a `x-goog-api-key`.

## N3-03 — podmíněné vendored kopie
- `whenRootExists` smí odkazovat pouze na kořen/prefix, pod kterým leží deklarovaná kopie.
- Nesoulad je fail-closed nález HIGH.
- Výstup checkeru explicitně vypisuje podmíněné kopie.

## Auditní režim
Verze je kandidát pro nezávislé ověření. SHIELD-LIVE, RI-LIVE a behaviorální AIR zůstávají mimo tento lokální runtime hardening.
