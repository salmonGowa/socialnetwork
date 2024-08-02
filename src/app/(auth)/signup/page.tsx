import { Metadata } from "next";
import signupImage from "@/assets/signup-image.jpg";
import Image from "next/image";
import Link from "next/link";
import { SignUpForm } from "./SignUpForm";

export const metadata: Metadata = {
  title: "Sign Up",
};

export default function page() {
  return (
    <main className="flex h-screen items-center justify-center p-5">
      <div className="bg-card flex h-full max-h-[40rem] w-full max-w-[64rem] overflow-hidden rounded-2xl shadow-2xl">
        <div className="md:w-1/2 w-full space-y-10 overflow-y-auto p-10">
        <div className="space-y-1 text-center">
            <h1 className="text-3xl font-bold ">Sign up to safeSpace</h1>
            <p className="text-muted-foreground">
                A place to let it all out
            </p>

        </div>
        <div className="space-y-5">
            <SignUpForm/>
            <Link href="/login" className="block text-center hover:underline">
            Already have an account? Log in
            
            </Link>
        </div>
        </div>
        <Image src={signupImage} alt="" className="w-1/2 hidden object-cover md:block" />
      </div>
    </main>
  );
}
