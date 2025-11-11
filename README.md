🧱 MLab.Portal.Bff — Backend (.NET 8 + Docker)

# 🧩 Pré-requisitos
- .NET 8 SDK
- Docker Desktop
- VS Code ou Visual Studio 2022 (opcional)

# ✅ Resumo
- CLI funciona com as portas corretas (8080)
- Build automatizado no GitHub Actions
- CI/CD integrado com Azure Container App (DEV)


# 🚀 Executar localmente via Docker (CLI)
Na raiz do projeto (mlab-new-backend), execute:

1. Construir a imagem do backend
docker build -t portal-bff:local -f MLab.Portal.Bff/Dockerfile .

2. Executar o container
docker run -p 8080:8080 portal-bff:local


# 📍 Depois, acesse no navegador:
http://localhost:8080/swagger
http://localhost:8080/swagger/index.html


# 🧰 Parar o container
Para parar o container rodando:

docker ps
docker stop <CONTAINER_ID>


# 🔧 Build + Deploy automáticos (GitHub Actions)
Os containers são automaticamente publicados em:

devmlabportalbff.azurecr.io/mlab-portal-bff:dev

através do workflow:

.github/workflows/deploy-dev.yml


# 🧪 Diagnóstico
O endpoint de diagnóstico está disponível apenas em ambiente DEV:

GET /api/diagnostics/env
http://localhost:8080/api/diagnostics/env
http://localhost:8080/api/diagnostics/ping


# 🧾 Autor
Hugo Leonardo Fernandes de Oliveira
MLab Portal — 2025