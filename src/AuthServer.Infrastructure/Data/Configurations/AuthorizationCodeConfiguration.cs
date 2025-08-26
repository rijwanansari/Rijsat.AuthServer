using AuthServer.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.Infrastructure.Data.Configurations;

public class AuthorizationCodeConfiguration : IEntityTypeConfiguration<AuthorizationCode>
{
    public void Configure(EntityTypeBuilder<AuthorizationCode> builder)
    {
        builder.ToTable("AuthorizationCodes");

        builder.HasKey(ac => ac.Code);

        builder.Property(ac => ac.Code)
            .HasMaxLength(100)
            .IsRequired();

        builder.HasIndex(ac => ac.ExpiresAt);
        builder.HasIndex(ac => ac.IsUsed);
        builder.HasIndex(ac => ac.UserId);
        builder.HasIndex(ac => ac.ClientId);

        // Configure relationships
        builder.HasOne(ac => ac.User)
            .WithMany()
            .HasForeignKey(ac => ac.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasOne(ac => ac.Client)
            .WithMany()
            .HasForeignKey(ac => ac.ClientId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
