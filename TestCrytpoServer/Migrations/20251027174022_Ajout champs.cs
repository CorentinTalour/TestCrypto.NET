using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace TestCrytpoServer.Migrations
{
    /// <inheritdoc />
    public partial class Ajoutchamps : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "CipherNameB64",
                table: "Secrets",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "CipherNotesB64",
                table: "Secrets",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "CipherURLB64",
                table: "Secrets",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "CipherNameB64",
                table: "Secrets");

            migrationBuilder.DropColumn(
                name: "CipherNotesB64",
                table: "Secrets");

            migrationBuilder.DropColumn(
                name: "CipherURLB64",
                table: "Secrets");
        }
    }
}
