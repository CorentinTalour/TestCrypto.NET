using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace TestCrytpoServer.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Vaults",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    OwnerUserId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    VaultSaltB64 = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Iterations = table.Column<int>(type: "int", nullable: false),
                    VerifierB64 = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Vaults", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Secrets",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    VaultId = table.Column<int>(type: "int", nullable: false),
                    CipherPasswordB64 = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    TagPasswordB64 = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IvPasswordB64 = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CipherNameB64 = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    TagNameB64 = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IvNameB64 = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CipherUrlB64 = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    TagUrlB64 = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IvUrlB64 = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CipherNotesB64 = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    TagNotesB64 = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IvNotesB64 = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Secrets", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Secrets_Vaults_VaultId",
                        column: x => x.VaultId,
                        principalTable: "Vaults",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Secrets_VaultId",
                table: "Secrets",
                column: "VaultId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Secrets");

            migrationBuilder.DropTable(
                name: "Vaults");
        }
    }
}
