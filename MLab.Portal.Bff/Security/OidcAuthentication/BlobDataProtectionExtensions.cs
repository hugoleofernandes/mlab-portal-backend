using Azure.Identity;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.DataProtection;

namespace MLab.Portal.Bff.Security.OidcAuthentication;

/// <summary>
/// Configures ASP.NET Core Data Protection to persist encryption keys in Azure Blob Storage.
/// In Development environments, the key ring is stored using the configured ConnectionString.
/// In Cloud/Production environments, access is performed securely using Managed Identity.
/// 
/// Persisting the Data Protection key ring in Blob Storage ensures that all containers,
/// replicas, or scaled-out instances of this application share the same cryptographic keys.
/// 
/// This is essential for authentication scenarios: it guarantees that cookies encrypted on 
/// one container can be decrypted by any other container, enabling true stateless
/// authentication and reliable load balancing in distributed deployments.
/// </summary>

public static class BlobDataProtectionExtensions
{
    public static IServiceCollection AddBlobDataProtection(
        this IServiceCollection services,
        IConfiguration config,
        IHostEnvironment env)
    {
        var container = config["DataProtection:BlobContainer"];
        var blobName = config["DataProtection:BlobName"];

        BlobClient blobClient;

        if (env.IsDevelopment())
        {
            var storageConn = config["Storage:ConnectionString"];
            blobClient = new BlobClient(storageConn, container, blobName);
        }
        else
        {
            var accountUrl = config["DataProtection:AccountUrl"];
            var uri = new Uri($"{accountUrl}/{container}/{blobName}");
            blobClient = new BlobClient(uri, new DefaultAzureCredential());
        }

        services.AddDataProtection()
            .PersistKeysToAzureBlobStorage(blobClient)
            .SetApplicationName("MLabPortalBFF");

        return services;
    }
}
