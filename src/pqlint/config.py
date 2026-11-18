"""Configuration settings and Mosca inequality assumptions for pqlint."""

from typing import Union

from pydantic import BaseModel, Field


class Config(BaseModel):
    """Configuration class holding global Mosca inequality assumptions.

    Attributes:
        shelf_life_years (X): How long sensitive data must remain protected (years).
                              Default is 10 years.
        migration_years (Y): How long the organization needs to migrate infrastructure
                             to post-quantum cryptography (years). Default is 3 years.
        crqc_years (Z): Estimated years until a Cryptographically Relevant Quantum
                        Computer (CRQC) is realized. Default is 12 years.
    """

    shelf_life_years: Union[int, float] = Field(
        default=10,
        ge=0,
        description="Data shelf life in years (X)",
    )
    migration_years: Union[int, float] = Field(
        default=3,
        ge=0,
        description="Migration timeline in years (Y)",
    )
    crqc_years: Union[int, float] = Field(
        default=12,
        gt=0,
        description="Estimated years until a CRQC exists (Z)",
    )

    @property
    def X(self) -> Union[int, float]:
        """Alias for shelf_life_years."""
        return self.shelf_life_years

    @property
    def Y(self) -> Union[int, float]:
        """Alias for migration_years."""
        return self.migration_years

    @property
    def Z(self) -> Union[int, float]:
        """Alias for crqc_years."""
        return self.crqc_years


# Default configuration instance
DEFAULT_CONFIG = Config()
