namespace Jeff.Jones.CryptoMgrTest
{
    /// <summary>
    /// This class is used when testing object encryption and decryption.
    /// </summary>
    public class TestPersonClass
    {
        public TestPersonClass()
        {
        }

        public String FirstName { get; set; } = "";
        public String LastName { get; set; } = "";
        
        public DateTime? BirthDate { get; set; } = null;

        public DateTime? DeathDate { get; set; } = null;

        public TestPersonChildClass MyList { get; set; } = new TestPersonChildClass();


    }

    public class TestPersonChildClass : List<String>
    {
        public TestPersonChildClass() : base()
        {
        }


    }
}
