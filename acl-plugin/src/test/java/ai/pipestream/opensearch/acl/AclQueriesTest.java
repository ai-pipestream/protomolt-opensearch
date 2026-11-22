package ai.pipestream.opensearch.acl;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.MatchAllQueryBuilder;
import org.opensearch.index.query.NestedQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.index.query.TermsQueryBuilder;

class AclQueriesTest {

    private static final AclFields FIELDS = new AclFields("acl_allow", "acl_gates", "allow", "acl_complete");

    @Test
    void accessRequiresCompleteAllowAndNoFailingGate() {
        BoolQueryBuilder access = (BoolQueryBuilder) AclQueries.access(FIELDS, List.of("alice", "grp:legal"));

        assertThat(access.filter()).hasSize(2);
        TermQueryBuilder complete = (TermQueryBuilder) access.filter().get(0);
        assertThat(complete.fieldName()).isEqualTo("acl_complete");
        assertThat(complete.value()).isEqualTo(true);
        TermsQueryBuilder allow = (TermsQueryBuilder) access.filter().get(1);
        assertThat(allow.fieldName()).isEqualTo("acl_allow");
        assertThat(allow.values()).containsExactly("alice", "grp:legal");

        NestedQueryBuilder gates = (NestedQueryBuilder) access.mustNot().get(0);
        assertThat(gates.path()).isEqualTo("acl_gates");
        BoolQueryBuilder gateFails = (BoolQueryBuilder) gates.query();
        TermsQueryBuilder gateAllow = (TermsQueryBuilder) gateFails.mustNot().get(0);
        assertThat(gateAllow.fieldName()).isEqualTo("acl_gates.allow");
        assertThat(gateAllow.values()).containsExactly("alice", "grp:legal");
    }

    @Test
    void accessMatchesNothingWithoutPrincipals() {
        BoolQueryBuilder access = (BoolQueryBuilder) AclQueries.access(FIELDS, List.of());

        assertThat(access.filter()).isEmpty();
        assertThat(access.mustNot()).singleElement().isInstanceOf(MatchAllQueryBuilder.class);
    }

    @Test
    void scopedAccessLetsOtherIndicesThrough() {
        BoolQueryBuilder scoped =
                (BoolQueryBuilder) AclQueries.accessForIndices(FIELDS, List.of("alice"), List.of("acl-docs"));

        assertThat(scoped.minimumShouldMatch()).isEqualTo("1");
        assertThat(scoped.should()).hasSize(2);
        BoolQueryBuilder otherIndices = (BoolQueryBuilder) scoped.should().get(1);
        TermsQueryBuilder index = (TermsQueryBuilder) otherIndices.mustNot().get(0);
        assertThat(index.fieldName()).isEqualTo("_index");
        assertThat(index.values()).containsExactly("acl-docs");
    }

    @Test
    void restrictKeepsOriginalQueryAsMust() {
        QueryBuilder original = QueryBuilders.matchQuery("title", "budget");
        QueryBuilder access = AclQueries.access(FIELDS, List.of("alice"));

        BoolQueryBuilder restricted = (BoolQueryBuilder) AclQueries.restrict(original, access);

        assertThat(restricted.must()).containsExactly(original);
        assertThat(restricted.filter()).containsExactly(access);
    }

    @Test
    void restrictWithoutOriginalQueryOnlyFilters() {
        QueryBuilder access = AclQueries.access(FIELDS, List.of("alice"));

        BoolQueryBuilder restricted = (BoolQueryBuilder) AclQueries.restrict(null, access);

        assertThat(restricted.must()).isEmpty();
        assertThat(restricted.filter()).containsExactly(access);
    }
}
