namespace Jeff.Jones.CryptoMgrTest
{
    /// <summary>
    /// This class is used when testing object encryption and decryption.
    /// </summary>
    public class TestPerson
    {
        public TestPerson()
        {
        }

        public String FirstName { get; set; } = "";
        public String LastName { get; set; } = "";
        
        public DateTime? BirthDate { get; set; } = null;

        public DateTime? DeathDate { get; set; } = null;

        public TestPersonChild MyList { get; set; } = new TestPersonChild();


    }

    public class TestPersonChild : List<String>
    {
        public TestPersonChild() : base()
        {
        }


    }
}
