using AsgardeoDotNetSample.Components;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using AsgardeoDotNetSample;

const string ASGARDEO_OIDC_SCHEME = "AsgardeoOidc";

var builder = WebApplication.CreateBuilder(args);

HttpClient httpClient;
if (Environment.GetEnvironmentVariable("HTTPCLIENT_VALIDATE_EXTERNAL_CERTIFICATES") == "false")
{
    var handler = new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
    };
    httpClient = new HttpClient(handler);
}
else
{
    httpClient = new HttpClient();
}

builder.Services.AddSingleton(httpClient);

builder.Services.AddAuthentication(ASGARDEO_OIDC_SCHEME)
    .AddOpenIdConnect(ASGARDEO_OIDC_SCHEME, oidcOptions =>
    {

        oidcOptions.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

        oidcOptions.Configuration = new ()
        {
            Issuer = Environment.GetEnvironmentVariable("TOKEN_ENDPOINT"),
            AuthorizationEndpoint = Environment.GetEnvironmentVariable("AUTHORIZATION_ENDPOINT"),
            TokenEndpoint = Environment.GetEnvironmentVariable("TOKEN_ENDPOINT"),
            JwksUri = Environment.GetEnvironmentVariable("JWKS_URI"),
            JsonWebKeySet = FetchJwks(Environment.GetEnvironmentVariable("JWKS_URI")!),
            EndSessionEndpoint = Environment.GetEnvironmentVariable("LOGOUT_URI"),
        };
        Console.WriteLine("Jwks: " + oidcOptions.Configuration.JsonWebKeySet);
        foreach (var key in oidcOptions.Configuration.JsonWebKeySet.GetSigningKeys())
        {
            oidcOptions.Configuration.SigningKeys.Add(key);
            Console.WriteLine("Added SigningKey: " + key.KeyId);
        }

        oidcOptions.Authority = Environment.GetEnvironmentVariable("AUTHORITY");

        oidcOptions.ClientId = Environment.GetEnvironmentVariable("CLIENT_ID");
        oidcOptions.ClientSecret = Environment.GetEnvironmentVariable("CLIENT_SECRET");

        oidcOptions.ResponseType = OpenIdConnectResponseType.Code;

        oidcOptions.MapInboundClaims = false;
        oidcOptions.TokenValidationParameters.NameClaimType = JwtRegisteredClaimNames.Name;
        oidcOptions.TokenValidationParameters.RoleClaimType = "roles";
        oidcOptions.MetadataAddress = Environment.GetEnvironmentVariable("METADATA_ADDRESS");
        oidcOptions.SaveTokens = true;
        oidcOptions.Scope.Add("internal_login");
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);

    JsonWebKeySet FetchJwks(string url)
    {
        var result = httpClient.GetAsync(url).Result;
        if (!result.IsSuccessStatusCode || result.Content is null)
        {
            throw new Exception(
                $"Getting token issuers (WSO2) JWKS from {url} failed. Status code {result.StatusCode}");
        }

        var jwks = result.Content.ReadAsStringAsync().Result;
        return new JsonWebKeySet(jwks);
    }

builder.Services.AddAuthorization();

builder.Services.AddCascadingAuthenticationState();

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddScoped<AuthenticationStateProvider, PersistingAuthenticationStateProvider>();

builder.Services.AddHttpContextAccessor();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapGroup("/authentication").MapLoginAndLogout();

app.Run();
