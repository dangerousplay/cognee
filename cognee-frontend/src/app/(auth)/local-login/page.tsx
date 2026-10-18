import AuthContentSectionCarousel from "@/ui/elements/Auth/ContentSections/AuthContentSectionCarousel";
import AuthPageContainer from "@/ui/elements/Auth/AuthPageContainer";
import LocalSignInForm from "./partials/LocalSignInForm";
import { Center, Flex } from "@mantine/core";
import { redirect } from "next/navigation";
import { getOidcLoginPath } from "@/modules/config/serverAuthMode";

export default function LocalLoginPage() {
  // With an external OIDC issuer there is no password form to show.
  const oidcLoginPath = getOidcLoginPath();
  if (oidcLoginPath) redirect(oidcLoginPath);

  return (
    <AuthPageContainer>
      <Center className="flex-1 flex-col">
        <Flex className="flex-col items-center w-full px-6 lg:w-[50vw] lg:px-0">
          <LocalSignInForm />
        </Flex>
      </Center>
      <AuthContentSectionCarousel />
    </AuthPageContainer>
  );
}
