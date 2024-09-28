namespace API_lvl_app.Models
{
    public class UpdatePasswordModel
    {
        public string PersonID { get; set; }
        public string ID { get; set; }
        public string IDDay { get; set; }
        public string BirthDay { get; set; }
        public string FactoryID { get; set; }
        public string NewPassword { get; set; }
    }
}
