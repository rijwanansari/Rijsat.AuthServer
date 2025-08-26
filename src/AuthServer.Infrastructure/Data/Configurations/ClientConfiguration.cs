using AuthServer.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.Infrastructure.Data.Configurations;

public class ClientConfiguration : IEntityTypeConfiguration<Client>
{
    public void Configure(EntityTypeBuilder<Client> builder)
    {
        builder.ToTable("Clients");

        builder.HasKey(c => c.Id);

        builder.Property(c => c.ClientId)
            .HasMaxLength(200)
            .IsRequired();

        builder.Property(c => c.ClientName)
            .HasMaxLength(200)
            .IsRequired();

        builder.Property(c => c.Description)
            .HasMaxLength(1000);

        builder.HasIndex(c => c.ClientId)
            .IsUnique();

        builder.HasIndex(c => c.IsActive);

        // Configure navigation properties
        builder.HasMany(c => c.ClientScopes)
            .WithOne(cs => cs.Client)
            .HasForeignKey(cs => cs.ClientId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasMany(c => c.ClientClaims)
            .WithOne(cc => cc.Client)
            .HasForeignKey(cc => cc.ClientId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasMany(c => c.RefreshTokens)
            .WithOne(rt => rt.Client)
            .HasForeignKey(rt => rt.ClientId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
