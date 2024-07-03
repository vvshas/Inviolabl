INVIOLABL
---------
Technologies: NextJS, Clerk, NestJS, Alchemy, Filecoin and Privy.

**Roles**

**Admin**
- sign ups
- creates org
- completes profile
- creates wallet, attach wallet & maintains wallet
- invites users
- does user mgmt for the org
- audits transaction on the wallet

**Non-Admin/Members**
- sign ups 
- joins invited org
- completes profile
- upload files and shares it with users (within org or outside org (email id)
- download shared files
- audits his own transactions on the platform
- views notification on the platform

**Basic flow** 
Admin of org1
- joins the platforms, creates the org1 and attaches a privy wallet to the org1 as part of the profile completion (enforce it before inviting the user or through other profile completion nudges)
- invites non-admin or admin users to the platform

Invited members join the org
- Admin/Non-admin members upload the file and share it within the org or outside the org (with email)
- Gas fee gets deducted for the upload and sharing and notification is sent to the other party
- The other user(org2) if is not part of the same org, creates and joins org2, and then attaches his wallet .. like admin of org 1
- The other user(org2) can download the file from the link(filecoin) by paying the gas fees (from the wallet of the parent org aka org2)
 
**Open Points**
- error handling use cases to be covered for the POC
- simplified stack i.e. clerk for identity and/or wallet through privy or alchemy
