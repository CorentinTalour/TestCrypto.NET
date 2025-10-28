using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace TestCrytpoServer.Migrations
{
    /// <inheritdoc />
    public partial class Test : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "CipherURLB64",
                table: "Secrets",
                newName: "CipherUrlB64");

            migrationBuilder.RenameColumn(
                name: "IvB64",
                table: "Secrets",
                newName: "IvUrlB64");

            migrationBuilder.RenameColumn(
                name: "CiphertextB64",
                table: "Secrets",
                newName: "IvPasswordB64");

            migrationBuilder.AddColumn<string>(
                name: "CipherPasswordB64",
                table: "Secrets",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "IvNameB64",
                table: "Secrets",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "IvNotesB64",
                table: "Secrets",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "CipherPasswordB64",
                table: "Secrets");

            migrationBuilder.DropColumn(
                name: "IvNameB64",
                table: "Secrets");

            migrationBuilder.DropColumn(
                name: "IvNotesB64",
                table: "Secrets");

            migrationBuilder.RenameColumn(
                name: "CipherUrlB64",
                table: "Secrets",
                newName: "CipherURLB64");

            migrationBuilder.RenameColumn(
                name: "IvUrlB64",
                table: "Secrets",
                newName: "IvB64");

            migrationBuilder.RenameColumn(
                name: "IvPasswordB64",
                table: "Secrets",
                newName: "CiphertextB64");
        }
    }
}
