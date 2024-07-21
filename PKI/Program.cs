using System.Globalization;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

internal class Program
{
    private static void Main(string[] args)
    {
        bool isRunning = true;
        while (isRunning)
        {
            Console.WriteLine("This is to practice various algorithms in cryptography");
            Console.WriteLine("Choose among the following:");
            Console.WriteLine("1: Diffie - Hellman Key Exchange");
            Console.WriteLine("2: RSA");
            Console.WriteLine("3: Encryption by ECC");
            int choice = int.Parse(Console.ReadLine());
            switch (choice)
            {
                case 1:
                    DH();
                    break;

                case 2:
                    RSA();
                    break;

                case 3:
                    ECC();
                    break;

                default:
                    Console.WriteLine("Invalid choice");
                    isRunning = false;
                    break;
            }
        }

        static void DH()
        {
            bool isRunning = true;
            Console.WriteLine("Diffie-Hellman Key Exchange");
            while (isRunning)
            {
                Console.WriteLine("Enter the modulus (p) which should be a prime number:");
                BigInteger modulus = BigInteger.Parse(Console.ReadLine());
                modulus = BigInteger.Abs(modulus);
                if (!IsPrime((int)modulus))
                {
                    Console.WriteLine("The number is not a prime number. Please enter a prime number.");
                    isRunning = false;
                    break;
                }
                Console.WriteLine("Enter the base number (g):");
                BigInteger baseNumber = BigInteger.Parse(Console.ReadLine());

                Console.WriteLine("Enter the secret of Bob (s):");
                BigInteger secretBob = BigInteger.Parse(Console.ReadLine());

                Console.WriteLine("Enter the secret of Carol (s):");
                BigInteger secretCarol = BigInteger.Parse(Console.ReadLine());

                Console.WriteLine("A of Bob:" + BigInteger.ModPow(baseNumber, secretBob, modulus));
                Console.WriteLine("A of Carol:" + BigInteger.ModPow(baseNumber, secretCarol, modulus));

                Console.WriteLine("Now we exchange the A values and compute the shared secret");
                Console.WriteLine("Enter the A of Carol:");
                BigInteger aBob = BigInteger.Parse(Console.ReadLine());
                Console.WriteLine("Enter the A of Bob:");
                BigInteger aCarol = BigInteger.Parse(Console.ReadLine());

                Console.WriteLine("K of Bob:" + BigInteger.ModPow(aBob, secretBob, modulus));
                Console.WriteLine("K of Carol:" + BigInteger.ModPow(aCarol, secretCarol, modulus));
                Console.WriteLine("The numbers above should be equal!");
                Console.WriteLine();
            }
        }

        static void RSA()
        {
            Console.WriteLine("RSA");

            Console.WriteLine("Give the first prime number p:");
            BigInteger p = BigInteger.Parse(Console.ReadLine());

            Console.WriteLine("Give the second prime number q:");
            BigInteger q = BigInteger.Parse(Console.ReadLine());
            BigInteger n = p * q;
            BigInteger phi = (p - 1) * (q - 1);

            Console.WriteLine("The number n is calculated by n = p * q:" + " " + n);
            Console.WriteLine("The number phi is calculated by phi = (p - 1) * (q - 1):" + phi);
            Console.WriteLine("Pick a prime number between 1 and phi:");
            BigInteger e = BigInteger.Parse(Console.ReadLine());
            Console.WriteLine("The public key is = (n, e) = (" + n + ", " + e + ")");

            BigInteger d = DiffieHellman.ModularMultiplicativeInverse(e, phi);
            Console.WriteLine("d: " + d);

            Console.WriteLine("The private key is (n, d) = (" + n + ", " + d + ")");

            Console.WriteLine("Encryption by public key");
            Console.WriteLine("Enter the word to encrypt:");
            //Read the letter to encrypt as a char:
            string letter = Console.ReadLine();
            BigInteger[] encryptedNumberArray = DiffieHellman.encryptedNumberArray(letter, e, n);
            for (int i = 0; i < encryptedNumberArray.Length; i++)
            {
                Console.WriteLine("The encrypted number is: " + encryptedNumberArray[i]);
            }

            //Decryption by private key using the method:
            BigInteger[] decryptedNumberArray = DiffieHellman.decryptedNumberArray(encryptedNumberArray, d, n);
            for (int i = 0; i < encryptedNumberArray.Length; i++)
            {
                Console.WriteLine("The decrypted number is: " + encryptedNumberArray[i]);
            }
            // Convert decrypted number array back to the word:
            string decryptedWord = "";
            for (int i = 0; i < decryptedNumberArray.Length; i++)
            {
                decryptedWord += (char)decryptedNumberArray[i];
            }
            // Display the decrypted word:
            Console.WriteLine("The decrypted word is: " + decryptedWord);
        }

        static bool IsPrime(int number)
        {
            if (number <= 1) return false; // 0 and 1 are not prime numbers
            if (number == 2) return true; // 2 is the only even prime number
            if (number % 2 == 0) return false; // Exclude even numbers greater than 2

            var boundary = (int)Math.Floor(Math.Sqrt(number));

            for (int i = 3; i <= boundary; i += 2)
            {
                if (number % i == 0) return false;
            }

            return true;
        }

        static void ECC()
        {
            Console.WriteLine("Encryption by ECC");
            // Elliptic curve parameters
            BigInteger a = 3;
            BigInteger b = 5;

            Console.WriteLine("Give P1 :");
            BigInteger x1 = BigInteger.Parse(Console.ReadLine());
            Console.WriteLine("Give P2 :");
            BigInteger x2 = BigInteger.Parse(Console.ReadLine());
            // Create point1
            EllipticCurvePoint P = new EllipticCurvePoint(x1, x2);

            Console.WriteLine("Give k1 :");
            BigInteger y1 = BigInteger.Parse(Console.ReadLine());
            Console.WriteLine("Give k2 :");
            BigInteger y2 = BigInteger.Parse(Console.ReadLine());
            // Create point2
            EllipticCurvePoint Q = new EllipticCurvePoint(y1, y2);

            // Warp the points in the method
            EllipticCurvePoint R = EllipticCurveOperations.AddPoints(P, Q, a, 7);
            // Diaplay the result
            Console.WriteLine("The result is: (" + R.X + ", " + R.Y + ")");
        }
    }

    public class DiffieHellman
    {
        // Generates a private key for one of the parties
        public static BigInteger GeneratePrivateKey(int keySize)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] bytes = new byte[keySize / 8];
                rng.GetBytes(bytes);
                return new BigInteger(bytes);
            }
        }

        // Computes the public key to be shared with the other party
        public static BigInteger ComputePublicKey(BigInteger privateKey, BigInteger baseNumber, BigInteger modulus)
        {
            return BigInteger.ModPow(baseNumber, privateKey, modulus);
        }

        // Computes the shared secret using the other party's public key
        public static BigInteger ComputeSharedSecret(BigInteger otherPartyPublicKey, BigInteger privateKey, BigInteger modulus)
        {
            return BigInteger.ModPow(otherPartyPublicKey, privateKey, modulus);
        }

        public static BigInteger ModularMultiplicativeInverse(BigInteger a, BigInteger m)
        {
            BigInteger m0 = m;
            BigInteger y = 0, x = 1;

            if (m == 1)
                return 0;

            while (a > 1)
            {
                // q is quotient
                BigInteger q = a / m;
                BigInteger t = m;

                // m is remainder now, process same as Euclid's algo
                m = a % m;
                a = t;
                t = y;

                // Update y and x
                y = x - q * y;
                x = t;
            }

            // Make x positive
            if (x < 0)
                x += m0;

            return x;
        }

        public static BigInteger[] encryptedNumberArray(string letter, BigInteger e, BigInteger n)
        {
            BigInteger[] encryptedNumberArray = new BigInteger[letter.Length];
            for (int i = 0; i < letter.Length; i++)
            {
                //Convert the char to a number:
                BigInteger number1 = (int)letter[i];
                // encrypt the number:
                BigInteger encryptedNumber = BigInteger.ModPow(number1, e, n);
                // Display the encrypted number:
                encryptedNumberArray[i] = encryptedNumber;
            }
            return encryptedNumberArray;
        }

        // Method to decrypt the encrypted number
        public static BigInteger[] decryptedNumberArray(BigInteger[] encryptedNumberArray, BigInteger d, BigInteger n)
        {
            BigInteger[] decryptedNumberArray = new BigInteger[encryptedNumberArray.Length];
            for (int i = 0; i < encryptedNumberArray.Length; i++)
            {
                // Decrypt the number:
                BigInteger decryptedNumber = BigInteger.ModPow(encryptedNumberArray[i], d, n);
                // Display the decrypted number:
                decryptedNumberArray[i] = decryptedNumber;
            }
            return decryptedNumberArray;
        }
    }

    public class EllipticCurvePoint
    {
        public BigInteger X { get; set; }
        public BigInteger Y { get; set; }

        public EllipticCurvePoint(BigInteger x, BigInteger y)
        {
            X = x;
            Y = y;
        }
    }

    public static class EllipticCurveOperations
    {
        public static EllipticCurvePoint AddPoints(EllipticCurvePoint P, EllipticCurvePoint Q, BigInteger a, BigInteger p)
        {
            if (P == null || Q == null)
                throw new ArgumentNullException("Points cannot be null.");

            // Check if one of the points is the point at infinity
            if (P.X == 0 && P.Y == 0) return Q;
            if (Q.X == 0 && Q.Y == 0) return P;

            BigInteger m;

            if (P.X == Q.X && P.Y == Q.Y) // Point doubling
            {
                m = (3 * P.X * P.X + a) * ModularMultiplicativeInverse(2 * P.Y, p) % p;
            }
            else // General case
            {
                m = (Q.Y - P.Y) * ModularMultiplicativeInverse(Q.X - P.X, p) % p;
            }

            BigInteger xR = (m * m - P.X - Q.X) % p;
            BigInteger yR = (m * (P.X - xR) - P.Y) % p;

            // Ensure xR and yR are positive
            xR = (xR + p) % p;
            yR = (yR + p) % p;

            return new EllipticCurvePoint(xR, yR);
        }

        private static BigInteger ModularMultiplicativeInverse(BigInteger a, BigInteger m)
        {
            BigInteger m0 = m;
            BigInteger y = 0, x = 1;

            if (m == 1)
                return 0;

            while (a > 1)
            {
                // q is quotient
                int q = (int)(a / m);
                BigInteger t = m;

                // m is remainder now, process same as Euclid's algo
                m = a % m;
                a = t;
                t = y;

                // Update y and x
                y = x - q * y;
                x = t;
            }

            // Make x positive
            if (x < 0)
                x += m0;

            return x;
        }
    }
}