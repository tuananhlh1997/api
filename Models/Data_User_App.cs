using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace API_lvl_app.Models;

[Table("Data_User_App")]
public partial class Data_User_App
{
    [Key]
    [StringLength(20)]
    [Unicode(false)]
    public string personID { get; set; }

    [StringLength(100)]
    [Unicode(false)]
    public string passWord { get; set; }

    [StringLength(100)]
    public string personName { get; set; }

    [StringLength(20)]
    [Unicode(false)]
    public string id { get; set; }

    public DateTime? idDay { get; set; }

    public DateTime? birthDay { get; set; }
    public string factoryID { get; set; }
    public string AccessToken { get; set; }
}