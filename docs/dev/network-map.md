# Cartographie réseau

L'onglet Cartographie utilise AntV G6 pour afficher les systèmes d'information,
les zones, les hôtes, les équipements et les liens fournis par les API `/map`.
Les données de scan TLS et les détails d'endpoints restent chargés depuis les
API existantes lors de la sélection d'un hôte.

Les tests unitaires de présentation et de navigation se trouvent dans
`frontend/src/__tests__/network-map-graph.test.ts` et
`frontend/src/__tests__/network-map.test.tsx`. Le parcours navigateur et ses
captures sont définis dans `tests/e2e/network-map.spec.ts`.

Pour vérifier localement le front-end :

```sh
cd frontend
npm ci
npm test
npm run build
```

Le parcours navigateur requiert l'instance de test Scan TLS disponible à
`https://localhost:15200` (ou une URL définie par `E2E_BASE_URL`) ainsi que ses
comptes et données de scénario.
