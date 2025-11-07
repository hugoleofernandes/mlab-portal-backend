# Etapa 1: Build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copia apenas o csproj primeiro (para aproveitar cache de restore)
COPY ["MLab.Portal.Bff.csproj", "./"]
RUN dotnet restore "MLab.Portal.Bff.csproj"

# Copia o restante do projeto e publica
COPY . .
RUN dotnet publish "MLab.Portal.Bff.csproj" -c Release -o /app/publish

# Etapa 2: Runtime
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app

# Porta padrão do Azure Container Apps
ENV ASPNETCORE_URLS=http://0.0.0.0:8080

COPY --from=build /app/publish .

ENTRYPOINT ["dotnet", "MLab.Portal.Bff.dll"]