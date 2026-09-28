# @e-sig/react playground

Local Vite harness for `SignaturePadCanvas` and `SelfSignFlow`. The development
server handles `POST /api/esign/sign` with a fixed success response, so the full
consent-and-submit interaction runs without credentials or external services.

From the repository root:

```bash
npm ci
npm run build -w @e-sig/react
npm run dev -w esig-react-playground
```

Open `http://localhost:5179`. The example uses only `@example.com` fixture data.
