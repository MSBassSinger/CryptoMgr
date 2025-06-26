namespace Jeff.Jones.CryptoMgrTest
{
    /// <summary>
    /// This class is used when testing object encryption and decryption.
    /// </summary>
    public class TestClass
    {
        public TestClass()
        {
        }

        public String FirstName { get; set; } = "";
        public String LastName { get; set; } = "";
        
        public DateTime? BirthDate { get; set; } = null;

        public DateTime? DeathDate { get; set; } = null;

        public TestChildClass MyList { get; set; } = new TestChildClass();


    }

    public class TestChildClass : List<String>
    {
        public TestChildClass() : base()
        {
        }


    }
}
