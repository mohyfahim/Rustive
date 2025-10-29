use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Client::Table)
                    .if_not_exists()
                    .col(pk_auto(Client::Id))
                    .col(string_null(Client::IPAddr).default(""))
                    .col(string_null(Client::MACAddr).default(""))
                    .col(boolean(Client::Auth).default(false))
                    .col(boolean(Client::WatchPortal).default(false))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Client::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Client {
    Table,
    Id,
    IPAddr,
    MACAddr,
    Auth,
    WatchPortal,
}
