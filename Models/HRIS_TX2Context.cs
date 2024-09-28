using Microsoft.EntityFrameworkCore;

namespace API_lvl_app.Models;

public partial class HRIS_TX2Context : DbContext
{
    public HRIS_TX2Context()
    {
    }

    public HRIS_TX2Context(DbContextOptions<HRIS_TX2Context> options)
        : base(options)
    {
    }

    public virtual DbSet<Data_User_App> Data_User_Apps { get; set; }


    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.UseCollation("Chinese_Taiwan_Stroke_CI_AS");

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}