# Mattes Antivirus

Ett antivirusprogram för Windows 11 som söker efter virus och annan malware.

## Status

Skannermotorn, kommandoradsprogrammet och det grafiska gränssnittet är på plats. Automatiska uppdateringar och installationsprogram kommer i nästa steg.

| Steg | Innehåll | Status |
| --- | --- | --- |
| 1 | Skanner: hash-signaturer, YARA-regler, karantän | Klar |
| 2 | Grafiskt gränssnitt (WPF) | Klar |
| 3 | Automatisk uppdatering av signaturer och programmet | Planerad |
| 4 | Installationsprogram och kodsignering | Planerad |

## Så hittar programmet hot

- **Hash-signaturer.** Varje fil får en SHA-256-hash som jämförs med hashar av känd malware. Signaturfilerna är vanliga textfiler med en rad per hash, `sha256` eller `sha256;Hotnamn`, så listor från till exempel [MalwareBazaar](https://bazaar.abuse.ch/) kan läsas in direkt.
- **YARA-regler.** Filernas innehåll matchas mot [YARA](https://virustotal.github.io/yara/)-regler, som känner igen mönster i malware även när filen har ändrats lite. Regelns `threat_name` blir hotets namn.
- **Karantän.** Hittade filer kan flyttas till karantän. Där sparas de kodade så att de inte kan köras av misstag, och de kan återställas eller raderas för gott.

Inbyggda signaturer och regler finns i [`signatures/`](signatures) och [`rules/`](rules). Nedladdade uppdateringar läggs i `%ProgramData%\MattesAntivirus\Signatures` och `...\Rules`.

## Programmet

`MattesAntivirus.exe` har tre sidor:

- **Översikt** visar om datorn är skyddad, när den senast skannades och hur många signaturer som är laddade. Härifrån startar du snabbskanning, fullständig skanning eller anpassad skanning av valda mappar.
- **Skanning** visar förloppet medan skanningen pågår och listar hoten efteråt. Markera hoten och flytta dem till karantän med en knapp.
- **Karantän** listar filer i karantän och låter dig återställa eller radera dem.

Filer i skyddade mappar, som `C:\Program Files`, kan bara flyttas till karantän om programmet körs som administratör.

## Kommandoraden

```
mattes-av scan C:\Users\Mattias\Downloads
mattes-av scan --quick --quarantine
mattes-av scan --full
mattes-av quarantine list
mattes-av quarantine restore <id>
mattes-av quarantine delete <id>
mattes-av info
```

Avslutningskoden är 0 när inga hot hittades, 1 när hot hittades och 2 vid fel.

Prova med [EICAR-testfilen](https://www.eicar.org/download-anti-malware-testfile/), en ofarlig fil som alla antivirusprogram känner igen. Stäng av Microsoft Defenders realtidsskydd för en testmapp först, annars tar Defender bort filen innan Mattes Antivirus hinner hitta den.

## Bygga

Kräver [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0).

```
dotnet build
dotnet test
dotnet publish src/MattesAntivirus.Cli -c Release -r win-x64 --self-contained false -o publish
```

YARA-motorn ([dnYara](https://github.com/airbus-cert/dnYara)) fungerar bara på 64-bitars Windows. På andra system skannar programmet bara med hash-signaturer.

## Projektets delar

- `src/MattesAntivirus.Core` – skanner, detektionsmotorer och karantän. Används av både kommandoraden och det grafiska programmet.
- `src/MattesAntivirus.App` – det grafiska programmet (WPF).
- `src/MattesAntivirus.Cli` – kommandoradsprogrammet `mattes-av`.
- `tests/MattesAntivirus.Core.Tests` – tester. De byggs och körs på Windows vid varje ändring via GitHub Actions.
