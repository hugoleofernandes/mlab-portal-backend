# Etapa 1: Build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copia o csproj e restaura dependências
COPY ["MLab.Portal.Bff/MLab.Portal.Bff.csproj", "MLab.Portal.Bff/"]
RUN dotnet restore "MLab.Portal.Bff/MLab.Portal.Bff.csproj"

# Copia o restante do projeto e publica
#COPY . .
#RUN dotnet publish "MLab.Portal.Bff.csproj" -c Release -o /app/publish

# Copia todo o código e publica
COPY . .
WORKDIR /src/MLab.Portal.Bff
RUN dotnet publish "MLab.Portal.Bff.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Etapa 2: Runtime
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app

# Porta padrão do Azure Container Apps
ENV ASPNETCORE_URLS=http://0.0.0.0:8080

COPY --from=build /app/publish .

EXPOSE 8080

ENTRYPOINT ["dotnet", "MLab.Portal.Bff.dll"]