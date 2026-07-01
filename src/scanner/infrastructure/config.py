"""
Configuration centralisée de l'application.

Utilise pydantic-settings pour lire les variables d'environnement
depuis le fichier .env et les valider au démarrage.

En NestJS, c'est l'équivalent de :
    ConfigModule.forRoot({ envFilePath: '.env' })
    @Inject(ConfigService) private config: ConfigService

Ici, on importe Settings() et on accède directement aux valeurs typées.
Si une variable obligatoire manque, l'app plante au démarrage avec un
message clair — pas au milieu d'un scan, 3 heures après le déploiement.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Chaque attribut correspond à une variable d'environnement.
    pydantic-settings fait la correspondance automatiquement :
        MONGO_URL dans .env → settings.mongo_url en Python

    Pourquoi des valeurs par défaut ici ?
    → En dev, on veut que ça marche out-of-the-box après un
      simple docker compose up. En prod, ces valeurs seraient
      écrasées par les vraies variables d'environnement.
    """

    mongo_url: str = "mongodb://localhost:27017"
    mongo_db: str = "scanner_db"
    redis_url: str = "redis://localhost:6379"
    log_level: str = "DEBUG"

    model_config = SettingsConfigDict(
        # Cherche un fichier .env à la racine du projet
        env_file=".env",
        # Si la variable existe dans l'env système ET dans .env,
        # l'env système gagne (utile en Docker/prod)
        env_file_encoding="utf-8",
    )


# Instance unique — importée partout via :
#   from scanner.infrastructure.config import settings
settings = Settings()
