# Azure PowerTool

Snelle overzichtsrapporten en opkuisacties voor Azure, volledig in je browser. Geen server, geen installatie: de tool is
een statische website (GitHub Pages) die met jouw eigen Microsoft-login rechtstreeks Azure Resource Manager, Resource
Graph en Microsoft Graph aanspreekt. Je ziet en doet dus nooit meer dan je account mag.

## Wat kan het?

| Pagina | Wat |
|---|---|
| **Mijn toegang** | Je account, tenants, subscriptions, Entra ID-rollen, Azure RBAC-rollen (direct, via groepen en via management groups), Graph-permissies, en per rapport of het met jouw rechten zal werken. |
| **Lege resourcegroepen** | Resourcegroepen zonder resources over alle subscriptions. Gevonden via Resource Graph en daarna gecontroleerd bij ARM. Lege groepen kan je per stuk of in bulk verwijderen (met bevestiging); vlak ervoor wordt elke groep nog eens gecontroleerd, en groepen met *Managed by* worden nooit verwijderd. |
| **Role assignments van verwijderde identiteiten** | RBAC-toewijzingen waarvan de principal (user, groep, service principal of managed identity) niet meer bestaat in Entra ID. Je kan toewijzingen per rij of in bulk (selectievakjes) verwijderen, telkens met bevestiging. Dat is uitgeschakeld als geen enkele principal teruggevonden werd (bv. gastaccount); de CSV-export bevat per rij het `az`-commando ervoor. |
| **App secrets & certificaten** | Secrets en certificaten van app registrations die verlopen zijn, binnen 60 dagen verlopen, langer dan een jaar geldig zijn of geen einddatum hebben. Met eigenaars en een `az`-commando om te roteren of op te ruimen. Optioneel worden alle Key Vaults doorzocht (alleen metadata) om te tonen in welke vault, subscription en onder welke naam het secret of certificaat staat. |
| **Open poorten naar internet** | Inbound NSG-regels die SSH, RDP, SMB, WinRM, databasepoorten of alle poorten openzetten voor `*` / `Internet` / `0.0.0.0/0`. |
| **Onveilige configuratie** | Storage (anonieme blob-toegang, HTTPS-only, TLS, netwerk, shared keys), Key Vault (purge protection, netwerk, RBAC), App Service (HTTPS-only) en SQL (publiek netwerk, TLS). Per bevinding de impact en de fix. |
| **Ongebruikte resources** | Ongekoppelde disks, public IP's, NIC's en NSG's, App Service plans zonder apps, en storage accounts zonder één transactie in de laatste 30 dagen (Azure Monitor-metrics, met de gebruikte capaciteit erbij; accounts jonger dan 30 dagen worden overgeslagen). Wat bewust zo blijft, kan je *aanvaarden* (met optionele reden): dan verdwijnt het uit het overzicht tot iemand de aanvaarding intrekt. |
| **Verweesde DNS-records** | A-, CNAME- en aliasrecords in private en publieke DNS-zones die nergens meer naar wijzen. Elk record krijgt een duidelijke status: **geverifieerd** (het IP ligt in een VNet/subnet dat je volledig kan zien en geen resource gebruikt het, of het CNAME-/aliasdoel bestaat aantoonbaar niet meer) of **niet verifieerbaar** (IP buiten elk zichtbaar VNet, of in een subnet met delegatie, dienst-instanties of IP-configuraties die je niet kan lezen), met de reden erbij. Scale set-NIC's (bv. AKS-nodes) worden apart opgehaald. Per record een `az`-commando om het op te ruimen. |
| **Publieke storage accounts** | Storage accounts met publieke netwerktoegang die door niets afgeschermd zijn: niet in een network security perimeter (NSP) in Enforced-modus (Learning telt standaard niet, en is met een filter toe te staan), geen tag `nsp` = `excluded` en geen goedgekeurde private endpoint. Ernst volgens de firewall (alle netwerken / geselecteerde netwerken / geen regels). Per account een `az`-commando om de publieke toegang uit te zetten of het account als uitzondering te taggen. |
| **SAS-gebruik op storage** | Storage accounts waar SAS-tokens aan staan (shared key-toegang), met het echte gebruik per authenticatietype over 7, 30 of 90 dagen: SAS, user delegation SAS, account key, Entra ID en anoniem (Azure Monitor-metric *Transactions*, dimensie *Authentication*). Accounts zonder key- of SAS-gebruik krijgen het `az`-commando om shared key-toegang uit te zetten. |
| **Activiteitenlog** | Elke wijziging vanuit de tool (verwijderde role assignments, aanvaardingen en intrekkingen): wie, wanneer, wat, en of het lukte. Opvragen van info wordt niet gelogd. |

Alle remediatierapporten hebben een filter op ernst en een kopieerknop per `az`-commando. De tool voert die commando's zelf niet uit.

Alles is **alleen-lezen**, met twee uitzonderingen: role assignments van verwijderde identiteiten en lege resourcegroepen kan je verwijderen. Voor role assignments heb je `Owner`, `User Access Administrator` of `Role Based Access Control Administrator` nodig op de scope, voor resourcegroepen `Contributor` of `Owner`.

## Logbestand: aanvaardingen en acties

Een website op GitHub Pages kan zelf niets bewaren. Aanvaardingen en de activiteitenlog gaan daarom naar **een JSON-bestand dat je zelf kiest**, bv. `AzurePowerTool-log.json` in je OneDrive. Links onderaan in de tool: *Logbestand* → **Nieuw…** of **Openen…**.

- Werkt in **Edge en Chrome** (File System Access API). Firefox en Safari kunnen geen bestanden schrijven; daar zijn aanvaarden en verwijderen uitgeschakeld.
- De browser onthoudt het bestand. Bij een volgend bezoek klik je één keer op **Toegang geven**.
- Zonder gekoppeld logbestand zijn verwijderen en aanvaarden uitgeschakeld: zonder logging wijzigt de tool niets.
- Elke schrijfactie leest het bestand eerst opnieuw in, zodat wijzigingen vanuit een ander tabblad of toestel (via OneDrive) niet verloren gaan. Het bestand is leesbare JSON; je kan het delen met collega's.

## Eenmalig instellen

### 1. App registration (Entra ID)

1. **Entra ID → App registrations → New registration**
   - Naam: `Azure PowerTool`
   - Supported account types: *Single tenant*. Kies *Multitenant* als je ook in andere tenants wil werken (tenant wisselen).
   - Redirect URI: platform **Single-page application (SPA)**, URL `https://<account>.github.io/AzurePowerTool/` (met de slash op het einde).
2. **Authentication**: voeg ook `http://localhost:5067/` toe als SPA-redirect om lokaal te ontwikkelen.
3. **API permissions → Add a permission** (delegated):
   - *Azure Service Management* → `user_impersonation`
   - *Microsoft Graph* → `User.Read`, `Directory.Read.All`
   - *Azure Key Vault* → `user_impersonation` (optioneel, voor de Key Vault-koppeling bij *App secrets & certificaten*)
4. **Grant admin consent** (`Directory.Read.All` vraagt dat).
5. Noteer de **Application (client) ID** en de **Directory (tenant) ID**.

Een SPA-registratie heeft geen secret: de client id en tenant id staan zichtbaar in de site, dat is normaal.

### 2. GitHub

1. **Settings → Pages → Source: GitHub Actions.**
2. **Settings → Secrets and variables → Actions → Variables**: `AZURE_CLIENT_ID` (de client id) en eventueel `AZURE_TENANT_ID`. Je kan ze ook rechtstreeks in [appsettings.json](src/AzurePowerTool.Web/wwwroot/appsettings.json) zetten.
3. Push naar `main`. De workflow [pages.yml](.github/workflows/pages.yml) bouwt en publiceert de site; de URL staat in de run (*deploy*).

Een site op GitHub Pages is publiek bereikbaar (behalve met private Pages in GitHub Enterprise). Er staan geen secrets in: zonder Microsoft-account met Azure-rechten ziet een bezoeker niets.

### 3. Netwerk

Je browser moet `login.microsoftonline.com`, `management.azure.com` en `graph.microsoft.com` kunnen bereiken (zoals de Azure-portal), en voor het DNS-rapport `cloudflare-dns.com`. Key Vaults alleen als ze bereikbaar zijn vanaf jouw netwerk (firewall / private endpoint).

## Lokaal ontwikkelen

Vereist: [.NET 10 SDK](https://dotnet.microsoft.com/download).

1. Maak `src/AzurePowerTool.Web/wwwroot/appsettings.Local.json` (staat niet in git):
   ```json
   { "Auth": { "ClientId": "<client id>", "TenantId": "<tenant id>" } }
   ```
2. Start:
   ```bash
   dotnet run --project src/AzurePowerTool.Web
   ```
   De browser opent op http://localhost:5067.

Het versienummer (onderaan de zijbalk) is `0.0.0-dev` bij lokale builds en `1.0.<run>` op GitHub Pages.

## Welke rechten heb je nodig?

- **Azure RBAC:** `Reader` op de subscriptions of management groups die je wil zien. Je ziet alleen wat je account mag lezen.
- **Entra ID:** gewone member-users kunnen standaard de directory lezen. **Gastaccounts** kunnen dat vaak niet, en dan is het rapport over role assignments van verwijderde identiteiten onbetrouwbaar. De pagina *Mijn toegang* waarschuwt daarvoor.
- **Key Vault (optioneel, voor *App secrets & certificaten*):** list-rechten op de vaults (RBAC `Key Vault Reader`, of een access policy met *List* op secrets en certificaten). Waarden van secrets worden nooit gelezen. Certificaten worden exact gekoppeld op thumbprint; secrets op app id of key id in naam/tags, vervaldatum of naam. Dat laatste is een inschatting, zie de kolom *Match*.

## Architectuur

```
src/
  AzurePowerTool.Core/        alle Azure-logica, geen UI (plain REST via HttpClient, geen Azure SDK's)
    Auth/                      IAzureSession: tokens per scope
    Clients/                   ArmClient, ResourceGraphClient, GraphClient, KeyVaultClient, DnsOverHttpsResolver
    Reports/                   één class per rapport
    Storage/                   AppData (aanvaardingen + activiteitenlog), AuditLog, AcknowledgementStore
  AzurePowerTool.Web/          Blazor WebAssembly (statische site)
    Auth/BrowserSession.cs     IAzureSession via MSAL.js (wwwroot/js/auth.js), redirect-login
    Storage/LogFileStore.cs    AppData in een gekozen bestand (wwwroot/js/logfile.js)
```

- **Resource Graph** doorzoekt in één KQL-query alle subscriptions. Zo blijft het snel, ook bij veel subscriptions.
- **Role assignments** komen uit `authorizationresources` met `AtScopeAboveAndBelow`, zodat ook toewijzingen op management group-niveau meekomen. Elke principal wordt via Graph `directoryObjects/getByIds` opgezocht (per 1000).
- **Aanmelden** gebeurt met MSAL.js (redirect naar Microsoft). Tokens staan in de `localStorage` van je browser, zodat je sessie een herstart overleeft. *Afmelden* wist ze uit deze browser.
- Een nieuw rapport is een class in `Core/Reports` plus een pagina die `ReportPageBase<T>` gebruikt.

## Bekende beperkingen

- Azure Resource Graph indexeert niet elk resourcetype. Daarom controleert het rapport lege resourcegroepen elke kandidaat nog rechtstreeks bij ARM.
- Toewijzingen aan een `ForeignGroup` (een groep uit een andere tenant) kunnen niet geverifieerd worden en worden apart gemarkeerd.
- Klassieke beheerders (co-administrators) en Azure Lighthouse-delegaties vallen buiten het rapport.
- PIM-rollen die *eligible* maar niet geactiveerd zijn, verschijnen niet in *Mijn toegang*.
- Key Vaults achter een firewall of private endpoint zijn vanuit je browser niet bereikbaar; ze worden gemeld als waarschuwing.
- CNAME-doelen worden publiek opgezocht (DNS-over-HTTPS via Cloudflare). Interne namen (on-premises DNS) zijn daar niet zichtbaar en krijgen status *niet verifieerbaar*.
