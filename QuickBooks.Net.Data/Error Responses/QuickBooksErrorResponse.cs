using System;

namespace QuickBooks.Net.Data.Error_Responses
{
    public class QuickBooksErrorResponse
    {
        public FaultResponse Fault;

        public long? Time;

        public override string ToString()
        {
            return $"{Time}: Response: {Fault}";
        }
    }
}
