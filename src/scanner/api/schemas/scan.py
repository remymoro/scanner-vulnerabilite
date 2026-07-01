"""
Schémas Pydantic pour l'API de scan.

Ce sont les DTOs (Data Transfer Objects) — ils définissent la forme
exacte des données qui ENTRENT et SORTENT de l'API.

En NestJS, c'est l'équivalent de :
    class CreateScanDto {
        @IsUrl()
        url: string;
    }

Ici, Pydantic valide automatiquement : si quelqu'un envoie
{ "url": "pas-une-url" }, FastAPI renvoie une 422 avec le détail
de l'erreur — sans qu'on écrive une seule ligne de validation.
"""

from pydantic import BaseModel, HttpUrl


class ScanRequest(BaseModel):
    """
    Ce que le client envoie pour lancer un scan.

    HttpUrl valide automatiquement que c'est une vraie URL avec
    un schéma (http:// ou https://). Pas besoin de regex maison.

    Exemple valide :   { "url": "https://example.com" }
    Exemple rejeté :   { "url": "pas-une-url" }  → 422
    Exemple rejeté :   { }                        → 422 (champ requis)
    """

    url: HttpUrl


class ScanResponse(BaseModel):
    """
    Ce que l'API renvoie immédiatement après avoir lancé un scan.

    Le scan tourne en arrière-plan — on ne fait pas attendre le client
    pendant 10 secondes. On lui donne un scan_id pour qu'il puisse
    récupérer les résultats plus tard (GET /report/{scan_id}).

    C'est le même pattern que dans ton stage : POST retourne un ID,
    GET récupère le rapport.
    """

    scan_id: str
    status: str = "pending"
    message: str = "Scan started"
